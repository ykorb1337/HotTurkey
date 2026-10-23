#!/usr/bin/env python3
"""Build a native .app and its helper using the macOS Command Line Tools."""
import json
import argparse
import os
import plistlib
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
BUILD=ROOT/"build"

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--qa",action="store_true",help="额外构建使用项目内测试数据的 QA 应用")
    parser.add_argument('--system-python',action='store_true',help='仅供开发：使用构建机 Python，不打包独立运行时')
    parser.add_argument('--archive',action='store_true',help='额外生成保留应用签名与链接的 ZIP 包')
    args=parser.parse_args()
    BUILD.mkdir(exist_ok=True)
    module_cache=BUILD/"swift-cache";module_cache.mkdir(exist_ok=True)
    targets=[("Agent.swift","HotTurkeyAgent",["AppKit","CoreGraphics"]),("Desktop.swift","HotTurkey",["AppKit","WebKit","UserNotifications"]),("PeerCheck.swift","HotTurkeyPeerCheck",["Foundation","Security"]),("PolicyClient.swift","HotTurkeyPolicyClient",["Foundation"])]
    if args.qa:
        targets.extend([("PeerFixture.swift","HotTurkeyPeerFixture",["Foundation"]),("PolicyClient.swift","HotTurkeyPolicyClientQA",["Foundation"])])
    for source,name,frameworks in targets:
        architecture='arm64' if platform.machine() in {'arm64','aarch64'} else 'x86_64'
        command=["/usr/bin/swiftc","-swift-version","5","-target",architecture+'-apple-macos12.0',"-O","-module-cache-path",str(module_cache),str(ROOT/"native"/source),"-o",str(BUILD/name)]
        if name=='HotTurkeyPolicyClientQA':command.extend(['-D','QA'])
        for framework in frameworks:command.extend(["-framework",framework])
        subprocess.run(command,check=True)
        if name in {"HotTurkeyAgent","HotTurkeyPeerCheck","HotTurkeyPeerFixture","HotTurkeyPolicyClient","HotTurkeyPolicyClientQA"}:
            subprocess.run(["/usr/bin/codesign","--force","--options","runtime","--sign","-",str(BUILD/name)],check=True)
    for name,flags in [('HotTurkeySystemAgent',[])]+([('HotTurkeySystemAgentQA',['-DHOTTURKEY_QA'])] if args.qa else []):
        subprocess.run(['/usr/bin/clang','-fobjc-arc','-O2','-Wall','-Wextra','-Werror','-mmacosx-version-min=12.0','-framework','Foundation',*flags,str(ROOT/'native/SystemAgent.m'),'-o',str(BUILD/name)],check=True)
        subprocess.run(['/usr/bin/codesign','--force','--options','runtime','--sign','-',str(BUILD/name)],check=True)
    app=BUILD/"HotTurkey.app/Contents"
    (app/"MacOS").mkdir(parents=True,exist_ok=True)
    resources=app/"Resources";resources.mkdir(exist_ok=True)
    shutil.copy2(BUILD/"HotTurkey",app/"MacOS/HotTurkey")
    project=resources/"project"
    project.mkdir(exist_ok=True)
    for name in ['README.md','LICENSE']:
        if (ROOT/name).is_file():shutil.copy2(ROOT/name,project/name)
    for folder in ["hotturkey","web","extension","scripts","docs"]:
        shutil.copytree(ROOT/folder,project/folder,dirs_exist_ok=True,ignore=shutil.ignore_patterns("__pycache__","*.pyc"))
    (project/"build").mkdir(exist_ok=True)
    shutil.copy2(BUILD/"HotTurkeyAgent",project/"build/HotTurkeyAgent")
    shutil.copy2(BUILD/"HotTurkeyPeerCheck",project/"build/HotTurkeyPeerCheck")
    shutil.copy2(BUILD/"HotTurkeyPolicyClient",project/"build/HotTurkeyPolicyClient")
    shutil.copy2(BUILD/'HotTurkeySystemAgent',project/'build/HotTurkeySystemAgent')
    python=resources/'python'
    third_party=resources/'ThirdParty/Python'
    if python.exists():shutil.rmtree(python)
    if third_party.exists():shutil.rmtree(third_party)
    if args.system_python:
        (resources/'python-path.txt').write_text(sys.executable)
    else:
        from prepare_runtime import prepare
        prepared=prepare()
        shutil.copytree(prepared/'python',python,symlinks=True)
        third_party.parent.mkdir(exist_ok=True)
        shutil.copytree(prepared/'licenses',third_party)
        shutil.copy2(prepared/'provenance.json',third_party/'provenance.json')
        (resources/'python-path.txt').write_text('python/bin/python3')
        # Python extension modules live outside Frameworks, so sign them explicitly.
        for path in sorted(python.rglob('*')):
            if path.is_symlink() or not path.is_file():continue
            with path.open('rb') as stream:magic=stream.read(4)
            if magic in {b'\xcf\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xca\xfe\xba\xbe',b'\xbe\xba\xfe\xca'}:
                subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(path)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    info={"CFBundleName":"HotTurkey","CFBundleDisplayName":"HotTurkey","CFBundleIdentifier":"local.hotturkey.desktop","CFBundleVersion":"3","CFBundleShortVersionString":"0.3.0","CFBundleExecutable":"HotTurkey","CFBundlePackageType":"APPL","LSMinimumSystemVersion":"12.0","NSHighResolutionCapable":True,"NSAppleEventsUsageDescription":"HotTurkey uses device rules to log out or shut down your Mac when you configure them.","NSAppTransportSecurity":{"NSAllowsLocalNetworking":True}}
    (app/"Info.plist").write_bytes(plistlib.dumps(info))
    # Ad-hoc signing allows local execution; distribution still needs a Developer ID.
    subprocess.run(["/usr/bin/codesign","--force","--deep","--sign","-",str(BUILD/"HotTurkey.app")],check=True)
    firefox=BUILD/"firefox-extension"
    shutil.copytree(ROOT/"extension",firefox,dirs_exist_ok=True)
    manifest=json.loads((firefox/"manifest.json").read_text())
    manifest["background"]={"scripts":["background.js"]}
    manifest["browser_specific_settings"]={"gecko":{"id":"hotturkey@local.hotturkey","strict_min_version":"128.0","data_collection_permissions":{"required":["none"]}}}
    manifest.pop("incognito",None)
    (firefox/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
    if args.qa:
        qa=BUILD/"HotTurkey QA.app"
        if qa.exists():shutil.rmtree(qa)
        shutil.copytree(BUILD/"HotTurkey.app",qa,symlinks=True)
        qa_info={**info,"CFBundleIdentifier":"local.hotturkey.qa","CFBundleDisplayName":"HotTurkey QA","HotTurkeyDataDirectory":str(ROOT/".runtime")}
        (qa/"Contents/Info.plist").write_bytes(plistlib.dumps(qa_info))
        subprocess.run(["/usr/bin/codesign","--force","--deep","--sign","-",str(qa)],check=True)
    print("Built:",BUILD/"HotTurkey.app")
    print("Browser extension:",ROOT/"extension")
    print('Python runtime:',sys.executable+' (development only)' if args.system_python else 'bundled, relocatable')
    if args.archive:
        archive=BUILD/('HotTurkey-macOS-'+platform.machine()+'.zip')
        subprocess.run(['/usr/bin/ditto','-c','-k','--sequesterRsrc','--keepParent',str(BUILD/'HotTurkey.app'),str(archive)],check=True)
        print('Archive:',archive)

if __name__=="__main__":main()
