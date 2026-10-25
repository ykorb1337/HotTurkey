#!/usr/bin/env python3
"""Prepare and inspect a protected-service payload without installing it."""
import argparse
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.ipc import decode_json
from hotturkey.system_package import (DAEMON,DATA,INSTALL,SOCKET_DIRECTORY,browser_binding,
                                      prepare_payload,verify_payload)
from hotturkey.session_launch import SESSION_PLIST


def main():
    parser=argparse.ArgumentParser(description='只准备可审查的系统安装材料，不写入系统目录或加载服务')
    parser.add_argument('--app-source',type=Path,default=ROOT/'build/HotTurkey.app')
    parser.add_argument('--output',type=Path,default=ROOT/'build/protected-payload')
    parser.add_argument('--browser-config',type=Path,help='JSON：浏览器名 → {app: 应用路径, origins: 扩展来源列表}')
    parser.add_argument('--controller-uid',type=int,default=os.getuid())
    parser.add_argument('--inspect',type=Path,help='仅核验已有安装材料')
    args=parser.parse_args()
    if os.geteuid()==0:parser.error('准备材料请使用普通账户运行，不需要管理员权限')
    if args.inspect:directory=args.inspect;value=verify_payload(directory)
    else:
        if not args.browser_config:parser.error('请明确指定浏览器和扩展来源配置')
        account=pwd.getpwuid(args.controller_uid)
        if account.pw_uid<500 or not account.pw_dir.startswith('/Users/') or account.pw_name.startswith('_'):parser.error('管理账户必须是本机普通用户')
        choices=decode_json(args.browser_config.read_bytes())
        if not isinstance(choices,dict) or not choices:parser.error('浏览器配置必须是非空对象')
        bindings={}
        for name,choice in choices.items():
            if not isinstance(choice,dict) or set(choice)!={'app','origins'}:parser.error('浏览器配置字段无效')
            bindings[name]=browser_binding(name,choice['app'],choice['origins'])
        directory=args.output;value=prepare_payload(args.app_source,directory,args.controller_uid,bindings)
    review={'payload':str(directory.absolute()),'controller_uid':value['controller_uid'],'app_version':value['app_version'],
            'file_entries':len(value['files']),'total_bytes':sum(entry.get('size',0) for entry in value['files'].values()),
            'planned_paths':{'program':str(INSTALL),'database':str(DATA),'socket_directory':str(SOCKET_DIRECTORY),
                             'daemon':str(DAEMON),'session_agent':str(SESSION_PLIST)},
            'system_files_written':False,'services_loaded':False,'rules_read_or_changed':False}
    print(json.dumps(review,ensure_ascii=False,indent=2))


if __name__=='__main__':
    try:main()
    except subprocess.CalledProcessError as error:
        message=error.stderr.decode(errors='replace') if isinstance(error.stderr,bytes) else error.stderr
        raise SystemExit(message or '安装材料签名校验失败') from None
    except (ValueError,OSError) as error:raise SystemExit(str(error)) from None
