import argparse
import json
import sys
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from .server import default_data

def main():
    parser=argparse.ArgumentParser(prog="hotturkey",description="HotTurkey 本地专注管理")
    parser.add_argument("--data",type=Path,default=default_data())
    parser.add_argument('--system',action='store_true',help='通过受保护原生客户端管理系统规则；需先完成系统安装')
    parser.add_argument("--settings-password",help="管理密码；也可在交互提示中输入")
    commands=parser.add_subparsers(dest="command",required=True)
    commands.add_parser("status")
    commands.add_parser("open")
    serve=commands.add_parser("serve");serve.add_argument("--enforce",action="store_true")
    for name in ["start","stop","toggle","delete","unlock","break","reset-pomodoro"]:
        p=commands.add_parser(name);p.add_argument("block");p.add_argument("--answer");p.add_argument("--confirm-device",action="store_true")
    p=commands.add_parser("lock");p.add_argument("block");p.add_argument("--minutes",type=int);p.add_argument("--password");p.add_argument("--text-length",type=int);p.add_argument("--delay",type=int);p.add_argument("--restart",action="store_true")
    p=commands.add_parser("add");p.add_argument("block");p.add_argument("rule");p.add_argument("--to",choices=["websites","exceptions","applications"],default="websites")
    p=commands.add_parser("create");p.add_argument("name");p.add_argument("--web",action="append",default=[]);p.add_argument("--app",action="append",default=[])
    p=commands.add_parser("check");p.add_argument("url")
    p=commands.add_parser("export");p.add_argument("file",type=Path)
    p=commands.add_parser("import");p.add_argument("file",type=Path)
    p.add_argument('--keep-autostart',action='store_true',help='明确保留导入规则的自动启动计划')
    p.add_argument('--confirm-device',action='store_true',help='确认保留设备自动启动，可能锁屏、注销或关机')
    p=commands.add_parser("stats");p.add_argument("--export",type=Path)
    args=parser.parse_args()
    if args.command=="serve":
        if args.system:
            if args.enforce:raise SystemExit('系统界面不启动当前用户执行器；请移除 --enforce')
            from .system_desktop import SystemDesktopService
            SystemDesktopService(args.data).run();return
        from .server import Service
        try:Service(args.data,enforce=args.enforce).run()
        except ValueError as exc:raise SystemExit(str(exc)) from None
        return
    try:
        if args.system:
            if args.command=='open':
                from .system_desktop import desktop_directory
                info=json.loads((desktop_directory(args.data)/'connection.json').read_text())
                if info.get('mode')!='system':raise ValueError('系统界面连接信息无效')
                webbrowser.open(f'http://127.0.0.1:{int(info["port"])}/#token={info["token"]}');return
            from .system_client import SystemClient
            system_client=SystemClient()
            info={'port':0,'token':''}
        else:info=json.loads((args.data/"connection.json").read_text())
        origin=f'http://127.0.0.1:{info["port"]}'
        session=""
        def call(path,data=None):
            if args.system:return system_client.api(path,data)
            request=urllib.request.Request(origin+"/api/"+path,data=json.dumps(data).encode() if data is not None else None,headers={"Authorization":"Bearer "+info["token"],"Content-Type":"application/json","X-HotTurkey-Session":session})
            try:
                with urllib.request.urlopen(request,timeout=10) as response:return json.load(response)
            except urllib.error.HTTPError as exc:
                raise ValueError(json.load(exc).get("error","操作失败")) from None
        if args.command=="open":webbrowser.open(origin+"/#token="+info["token"]);return
        state=call("state")
        if not state["authenticated"] and args.command not in {"status","check"} and state.get('can_manage',True):
            import getpass
            password=args.settings_password or getpass.getpass("设置密码：")
            session=call("auth",{"password":password})["session"]
            state=call("state")
        ident=None
        if hasattr(args,"block"):
            b=next((x for x in state["blocks"] if x["name"]==args.block or x["id"]==args.block),None)
            if not b:raise ValueError("找不到该规则")
            ident=b["id"]
        command=args.command
        if command=="status":result=state
        elif command in {"start","stop","toggle"}:result=call("blocks/toggle",{"id":ident,"enabled":{"start":True,"stop":False,"toggle":None}[command],"confirm_device":args.confirm_device})
        elif command in {"delete","unlock","break","reset-pomodoro"}:result=call("blocks/"+command,{"id":ident,"answer":args.answer} if args.answer is not None else {"id":ident})
        elif command=="create":result=call("blocks/save",{"block":{"name":args.name,"websites":args.web,"applications":args.app}})
        elif command=="lock":
            data={"id":ident}
            if args.minutes:data.update(type="timer",until=state["now"]+args.minutes*60)
            elif args.password:data.update(type="password",password=args.password)
            elif args.text_length:data.update(type="text",length=args.text_length)
            elif args.delay:data.update(type="delay",minutes=args.delay)
            elif args.restart:data.update(type="restart")
            else:raise ValueError("请指定锁定方式")
            result=call("blocks/lock",data)
        elif command=="add":
            if args.to in {"websites","applications"}:result=call("blocks/add-targets",{"id":ident,args.to:[args.rule]})
            else:
                b[args.to].append(args.rule);result=call("blocks/save",{"id":ident,"block":b})
        elif command=="check":result=call("check",{"url":args.url,"record":False})
        elif command=="export":args.file.write_text(json.dumps(call("export"),ensure_ascii=False,indent=2));result={"file":str(args.file)}
        elif command=="import":
            value=json.loads(args.file.read_text())
            if not isinstance(value,dict) or not isinstance(value.get('blocks'),list):raise ValueError('请选择包含规则列表的导出文件')
            blocks=value['blocks']
            if args.keep_autostart and not args.confirm_device and any(isinstance(b,dict) and b.get('device','none')!='none' and isinstance(b.get('autostart'),dict) and b['autostart'].get('type','none')!='none' for b in blocks):raise ValueError('保留设备自动启动须明确指定 --confirm-device')
            if not args.keep_autostart:blocks=[{**b,'autostart':{'type':'none'}} if isinstance(b,dict) else b for b in blocks]
            result=call('import',{'blocks':blocks,'allow_autostart':args.keep_autostart,'confirm_device':args.confirm_device})
        elif command=="stats":
            result=call("statistics/export" if args.export else "statistics")
            if args.export:args.export.write_text(json.dumps(result,ensure_ascii=False,indent=2));result={"file":str(args.export)}
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (OSError,ValueError,KeyError) as exc:
        print(str(exc),file=sys.stderr);raise SystemExit(1)

if __name__=="__main__":main()
