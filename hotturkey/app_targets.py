"""Resolve app launchers to their real installed targets without executing them."""
import functools
import plistlib
import re
import time
from pathlib import Path
from xml.parsers.expat import ExpatError

MAX_METADATA=4*1024*1024


def read_metadata(path):
    with Path(path).open('rb') as stream:data=stream.read(MAX_METADATA+1)
    if len(data)>MAX_METADATA:raise ValueError('Application metadata is too large')
    return data


def app_info(path):
    try:
        data=read_metadata(Path(path)/'Contents/Info.plist')
        # Steam's macOS shortcut generator appends NUL bytes to its XML plist.
        if not data.startswith(b'bplist'):data=data.rstrip(b'\0')
        info=plistlib.loads(data)
        return info if isinstance(info,dict) else {}
    except (OSError,ValueError,plistlib.InvalidFileException,ExpatError):return {}


def key_values(data):
    """The bounded quoted-string/braces subset used by Steam library manifests."""
    text=data.decode('utf-8-sig')
    token=re.compile(r'\s+|//[^\n]*|"((?:[^"\\]|\\.)*)"|([{}])')
    stack=[{}];pending=None;offset=0;count=0
    while offset<len(text):
        match=token.match(text,offset)
        if match is None:raise ValueError('Invalid Steam manifest')
        offset=match.end();count+=1
        if count>100000:raise ValueError('Steam manifest too complex')
        if match.group(1) is not None:
            value=re.sub(r'\\(["\\])',r'\1',match.group(1))
            if pending is None:pending=value
            else:stack[-1][pending]=value;pending=None
        elif match.group(2)=='{':
            if pending is None or len(stack)>12:raise ValueError('Invalid Steam manifest nesting')
            child={};stack[-1][pending]=child;stack.append(child);pending=None
        elif match.group(2)=='}':
            if pending is not None or len(stack)==1:raise ValueError('Invalid Steam manifest nesting')
            stack.pop()
    if len(stack)!=1 or pending is not None:raise ValueError('Incomplete Steam manifest')
    return stack[0]


def steam_shortcut_id(path):
    app=Path(path)
    executable=app_info(app).get('CFBundleExecutable')
    if not isinstance(executable,str) or Path(executable).name!=executable:return None
    try:text=read_metadata(app/'Contents/MacOS'/executable).decode('utf-8')
    except (OSError,ValueError,UnicodeError):return None
    for line in text.splitlines():
        match=re.fullmatch(r'\s*(?:/usr/bin/)?open\s+[\"\']?steam://(?:run|rungameid)/([1-9][0-9]{0,19})/?[\"\']?\s*',line)
        if match:return match.group(1)
    return None


class ApplicationTargets:
    def __init__(self, steam_root=None, app_roots=None, clock=time.monotonic):
        self.steam_root=Path(steam_root) if steam_root is not None else Path.home()/'Library/Application Support/Steam'
        self.app_roots=tuple(Path(p) for p in app_roots) if app_roots is not None else (Path('/Applications'),Path('/System/Applications'),Path.home()/'Applications')
        self.clock=clock

    def __call__(self, rule):return self.resolve(rule,int(self.clock()/5))

    @functools.lru_cache(maxsize=512)
    def resolve(self, rule, generation):
        targets=[rule]
        if rule.startswith('steam:'):
            appid=rule[6:]
            if re.fullmatch(r'[1-9][0-9]{0,19}',appid):targets.extend(self.steam_targets(appid,generation))
        elif rule.startswith('bundle:'):
            targets.extend('folder:'+str(path) for bundle,path in self.bundle_paths(generation) if bundle==rule[7:])
        elif rule.startswith('/') and rule.endswith('.app'):
            path=Path(rule)
            bundle=app_info(path).get('CFBundleIdentifier')
            if isinstance(bundle,str) and bundle:targets.append('bundle:'+bundle)
            appid=steam_shortcut_id(path)
            if appid:targets.extend(self.steam_targets(appid,generation))
        return tuple(dict.fromkeys(targets))

    @functools.lru_cache(maxsize=2)
    def bundle_paths(self, generation):
        paths=[]
        children=[]
        for parent in self.app_roots:
            try:children.extend(parent.glob('*.app'))
            except OSError:continue
        # Steam's installed client can be a bundle directory named "Steam"
        # without .app, separate from the /Applications bootstrap application.
        children.extend([self.steam_root/'Steam.AppBundle/Steam',self.steam_root/'Steam.AppBundle/Steam.app'])
        for path in children:
            bundle=app_info(path).get('CFBundleIdentifier')
            if isinstance(bundle,str) and bundle:paths.append((bundle,path))
        return tuple(paths)

    @functools.lru_cache(maxsize=2)
    def steam_libraries(self, generation):
        paths=[self.steam_root]
        for filename in ['steamapps/libraryfolders.vdf','config/libraryfolders.vdf']:
            try:value=key_values(read_metadata(self.steam_root/filename))
            except (OSError,ValueError,UnicodeError):continue
            folders=next((v for k,v in value.items() if k.casefold()=='libraryfolders'),{})
            if not isinstance(folders,dict):continue
            for key,item in folders.items():
                if not key.isdigit():continue
                path=item.get('path') if isinstance(item,dict) else item
                if isinstance(path,str) and path.startswith('/') and not any(ord(c)<32 for c in path):paths.append(Path(path))
        return tuple(dict.fromkeys(paths))

    @functools.lru_cache(maxsize=512)
    def steam_targets(self, appid, generation):
        result=[]
        for library in self.steam_libraries(generation):
            try:value=key_values(read_metadata(library/'steamapps'/f'appmanifest_{appid}.acf'))
            except (OSError,ValueError,UnicodeError):continue
            state=next((v for k,v in value.items() if k.casefold()=='appstate'),{})
            if not isinstance(state,dict) or state.get('appid')!=appid:continue
            directory=state.get('installdir')
            if not isinstance(directory,str) or directory in {'','.','..'} or '/' in directory or '\\' in directory or any(ord(c)<32 for c in directory):continue
            result.append('folder:'+str(library/'steamapps/common'/directory))
        return tuple(result)
