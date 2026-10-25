"""Reviewable protected-installation payloads. Never writes system paths.

The manifest is an integrity inventory, not a publisher signature. Administrator
approval of the complete artifact remains necessary before privileged use.
"""
import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
from pathlib import Path

from .ipc import decode_json
from .session_launch import INSTALL,session_launch_agent

HELPERS=('HotTurkeyPeerCheck','HotTurkeyPolicyClient','HotTurkeySystemAgent','HotTurkeySessionAgent','HotTurkeyBrowserHost')
ROLES={'client':'HotTurkeyPolicyClient','session':'HotTurkeySessionAgent','browser':'HotTurkeyBrowserHost'}
LABEL='local.hotturkey.authority'
DATA=Path('/private/var/db/local.hotturkey')
SOCKET_DIRECTORY=Path('/private/var/run/local.hotturkey')
DAEMON=Path('/Library/LaunchDaemons')/(LABEL+'.plist')
BROWSER_IDS={'Edge':'com.microsoft.edgemac','Chrome':'com.google.Chrome','Firefox':'org.mozilla.firefox',
             'Brave':'com.brave.Browser','Opera':'com.operasoftware.Opera','Vivaldi':'com.vivaldi.Vivaldi'}


def digest(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):result.update(chunk)
    return result.hexdigest()


def inventory(directory,*,ignore_manifest=False):
    """Inspect without following directory links; permit only internal file links."""
    directory=Path(directory).absolute();result={};total=0
    if directory.is_symlink() or not directory.is_dir():raise ValueError('安装包目录无效')
    directory=directory.resolve(strict=True)
    for parent,folders,files in os.walk(directory,followlinks=False):
        for name in sorted(folders+files):
            path=Path(parent)/name;relative=path.relative_to(directory).as_posix()
            if ignore_manifest and relative=='payload.json':continue
            info=path.lstat()
            if info.st_mode&0o7000:raise ValueError('安装包包含特殊权限')
            if stat.S_ISLNK(info.st_mode):
                target=os.readlink(path)
                if os.path.isabs(target):raise ValueError('安装包包含绝对链接')
                try:resolved=path.resolve(strict=True);resolved.relative_to(directory)
                except (ValueError,OSError,RuntimeError):raise ValueError('安装包链接越界或失效') from None
                if not resolved.is_file():raise ValueError('安装包目录不能是链接')
                result[relative]={'type':'link','target':target}
            elif stat.S_ISDIR(info.st_mode):result[relative]={'type':'directory','mode':stat.S_IMODE(info.st_mode)}
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink!=1:raise ValueError('安装包不能包含硬链接')
                total+=info.st_size
                result[relative]={'type':'file','mode':stat.S_IMODE(info.st_mode),'size':info.st_size,'sha256':digest(path)}
            else:raise ValueError('安装包包含非常规文件')
            if len(result)>30000 or total>2*1024**3:raise ValueError('安装包过大')
    return dict(sorted(result.items()))


def normalize_permissions(directory):
    for parent,folders,files in os.walk(directory,followlinks=False):
        Path(parent).chmod(0o755)
        for name in files:
            path=Path(parent)/name
            if not path.is_symlink():path.chmod(0o755 if path.stat().st_mode&0o111 else 0o644)


def daemon_plan():
    return {'Label':LABEL,'ProgramArguments':[str(INSTALL/'HotTurkey.app/Contents/Resources/python/bin/python3'),
            '-I','-B',str(INSTALL/'authority-entry.py')],'WorkingDirectory':str(INSTALL),
            'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':5,'ExitTimeOut':15,
            'ProcessType':'Background','Umask':0o077,'StandardOutPath':'/dev/null','StandardErrorPath':'/dev/null',
            'EnvironmentVariables':{'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/var/root'}}


def authority_entry():
    return 'import runpy, sys\nsys.path.insert(0, '+repr(str(INSTALL/'project'))+')\nrunpy.run_module("hotturkey.authority_server", run_name="__main__")\n'


def validate_bindings(bindings):
    if not isinstance(bindings,dict) or not bindings or set(bindings)-set(BROWSER_IDS):raise ValueError('必须指定实际使用的浏览器')
    for name,value in bindings.items():
        if not isinstance(value,dict) or set(value)!={'requirement','origins'}:raise ValueError('浏览器绑定字段无效')
        requirement=value['requirement'];origins=value['origins']
        if not isinstance(requirement,str) or not 1<=len(requirement.encode())<=4096:raise ValueError('浏览器签名要求无效')
        if not isinstance(origins,list) or not 1<=len(origins)<=32 or any(not isinstance(origin,str) for origin in origins) or len(set(origins))!=len(origins):raise ValueError('浏览器扩展范围无效')
        for origin in origins:
            if not isinstance(origin,str) or not (origin=='hotturkey@local.hotturkey' if name=='Firefox' else re.fullmatch(r'chrome-extension://[a-p]{32}/',origin)):
                raise ValueError('浏览器扩展来源无效')


def native_requirement(checker,executable):
    result=subprocess.run([str(checker),'--describe',str(executable)],check=True,capture_output=True,timeout=10)
    value=decode_json(result.stdout)
    if (not isinstance(value,dict) or value.get('ok') is not True or value.get('restricted_runtime') is not True
            or not isinstance(value.get('requirement'),str) or not re.fullmatch(r'cdhash H"[0-9a-f]{40}"',value['requirement'])):raise ValueError('原生助手需要无调试例外的加固运行时签名')
    return value['requirement']


def verify_signature(app):
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True,capture_output=True,timeout=60)


def browser_binding(name,app,origins):
    """Pin the chosen, verified Developer-ID browser's own designated requirement."""
    app=Path(app);info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
    if name not in BROWSER_IDS or info.get('CFBundleIdentifier')!=BROWSER_IDS[name]:raise ValueError('浏览器应用身份不匹配')
    result=subprocess.run(['/usr/bin/codesign','-d','-r','-',str(app)],check=True,capture_output=True,text=True,timeout=10)
    lines=[line.removeprefix('designated => ') for line in (result.stdout+'\n'+result.stderr).splitlines() if line.startswith('designated => ')]
    if len(lines)!=1 or 'anchor apple generic' not in lines[0] or 'subject.OU' not in lines[0]:raise ValueError('浏览器需要有效的开发者签名')
    # Match BrowserHost's Security-framework flags=0 validation. Strict bundle
    # hygiene additionally rejects harmless Finder metadata on installed apps.
    subprocess.run(['/usr/bin/codesign','--verify','-R','='+lines[0],str(app)],check=True,capture_output=True,timeout=30)
    value={name:{'requirement':lines[0],'origins':list(origins)}};validate_bindings(value)
    return value[name]


def prepare_payload(app,destination,controller_uid,bindings):
    if type(controller_uid) is not int or not 500<=controller_uid<=4294967295:raise ValueError('管理账户 UID 无效')
    validate_bindings(bindings);app=Path(app);destination=Path(destination)
    info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
    if info.get('CFBundleIdentifier')!='local.hotturkey.desktop' or 'HotTurkeyDataDirectory' in info:raise ValueError('需要正式构建的 HotTurkey.app')
    resources=app/'Contents/Resources'
    if (resources/'python-path.txt').read_text().strip()!='python/bin/python3':raise ValueError('系统安装必须使用应用内独立运行时')
    if {path.name for path in (resources/'project/build').iterdir()}!=set(HELPERS)|{'HotTurkeyAgent'}:raise ValueError('正式应用包含测试助手或未知执行文件')
    inventory(app);verify_signature(app)
    if destination.exists() or destination.is_symlink():raise FileExistsError('安装包目标已存在')
    destination.mkdir(mode=0o700)
    try:
        installed_app=destination/'HotTurkey.app';shutil.copytree(app,installed_app,symlinks=True)
        info['HotTurkeySystemMode']=True;(installed_app/'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(installed_app)],check=True,capture_output=True,timeout=60)
        verify_signature(installed_app)
        source=installed_app/'Contents/Resources/project'
        shutil.copytree(source/'hotturkey',destination/'project/hotturkey',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        for name in HELPERS:shutil.copy2(source/'build'/name,destination/name)
        requirements={role:native_requirement(destination/'HotTurkeyPeerCheck',destination/name) for role,name in ROLES.items()}
        if len(set(requirements.values()))!=3:raise ValueError('原生助手角色必须具有不同签名')
        (destination/'authority.json').write_text(json.dumps({'version':3,'controller_uid':controller_uid,'requirements':requirements},indent=2))
        (destination/'browsers.json').write_text(json.dumps({'version':1,'browsers':bindings},indent=2))
        # Isolated Python omits user sites, environment and the working directory.
        (destination/'authority-entry.py').write_text(authority_entry())
        (destination/'authority.plist').write_bytes(plistlib.dumps(daemon_plan()))
        (destination/'session.plist').write_bytes(plistlib.dumps(session_launch_agent()))
        normalize_permissions(destination)
        value={'version':1,'controller_uid':controller_uid,'app_version':info['CFBundleShortVersionString'],'files':inventory(destination,ignore_manifest=True)}
        (destination/'payload.json').write_text(json.dumps(value,sort_keys=True,indent=2));(destination/'payload.json').chmod(0o644)
        verify_payload(destination)
        return value
    except BaseException:
        shutil.rmtree(destination);raise


def verify_payload(directory):
    directory=Path(directory);manifest=directory/'payload.json'
    if (manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size>8*1024**2
            or stat.S_IMODE(manifest.stat().st_mode)!=0o644 or manifest.stat().st_nlink!=1):raise ValueError('安装清单无效')
    value=decode_json(manifest.read_bytes())
    if not isinstance(value,dict) or set(value)!={'version','controller_uid','app_version','files'} or type(value['version']) is not int or value['version']!=1:raise ValueError('安装清单版本无效')
    if type(value['controller_uid']) is not int or not 500<=value['controller_uid']<=4294967295:raise ValueError('管理账户 UID 无效')
    if inventory(directory,ignore_manifest=True)!=value['files']:raise ValueError('安装包文件与清单不一致')
    if any(entry.get('mode') not in {0o644,0o755} for entry in value['files'].values() if entry['type']!='link'):raise ValueError('安装包权限不是标准只读配置')
    expected=set(HELPERS)|{'HotTurkey.app','project','authority.json','browsers.json','authority-entry.py','authority.plist','session.plist','payload.json'}
    if {path.name for path in directory.iterdir()}!=expected:raise ValueError('安装包包含未识别的根目录项目')
    app=directory/'HotTurkey.app';verify_signature(app)
    metadata=plistlib.loads((app/'Contents/Info.plist').read_bytes())
    if (metadata.get('CFBundleIdentifier')!='local.hotturkey.desktop' or metadata.get('HotTurkeySystemMode') is not True
            or 'HotTurkeyDataDirectory' in metadata or metadata.get('CFBundleShortVersionString')!=value['app_version']):raise ValueError('系统应用元数据无效')
    canonical=app/'Contents/Resources/project'
    if {path.name for path in (canonical/'build').iterdir()}!=set(HELPERS)|{'HotTurkeyAgent'}:raise ValueError('正式应用包含测试助手或未知执行文件')
    if inventory(directory/'project/hotturkey')!=inventory(canonical/'hotturkey'):raise ValueError('策略源文件与签名应用不一致')
    if {path.name for path in (directory/'project').iterdir()}!={'hotturkey'}:raise ValueError('策略目录包含额外代码')
    if (directory/'authority-entry.py').read_text()!=authority_entry():raise ValueError('系统启动入口不是固定程序')
    for name in HELPERS:
        if digest(directory/name)!=digest(canonical/'build'/name):raise ValueError('原生助手与签名应用不一致')
    config=decode_json((directory/'authority.json').read_bytes())
    if set(config)!={'version','controller_uid','requirements'} or config['version']!=3 or config['controller_uid']!=value['controller_uid']:raise ValueError('策略配置不一致')
    requirements=config['requirements']
    if not isinstance(requirements,dict) or set(requirements)!=set(ROLES) or any(not isinstance(item,str) for item in requirements.values()) or len(set(requirements.values()))!=3:raise ValueError('原生角色配置无效')
    if any(not isinstance(requirement,str) or not re.fullmatch(r'cdhash H"[0-9a-f]{40}"',requirement) for requirement in requirements.values()):raise ValueError('原生角色签名无效')
    if any(native_requirement(directory/'HotTurkeyPeerCheck',directory/name)!=requirements[role] for role,name in ROLES.items()):raise ValueError('签名角色与实际助手不一致')
    browsers=decode_json((directory/'browsers.json').read_bytes())
    if set(browsers)!={'version','browsers'} or browsers['version']!=1:raise ValueError('浏览器配置无效')
    validate_bindings(browsers['browsers'])
    if plistlib.loads((directory/'authority.plist').read_bytes())!=daemon_plan() or plistlib.loads((directory/'session.plist').read_bytes())!=session_launch_agent():raise ValueError('启动计划不是固定系统路径')
    return value
