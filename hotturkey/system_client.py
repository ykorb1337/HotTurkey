"""Unprivileged adapter to the fixed, protected native policy client.

No root database, socket path, UID, credentials or filesystem actions are
selected by an API request. Test-only commands are injected programmatically.
"""
import json
import subprocess
from pathlib import Path

from .documents import MAX_DOCUMENT
from .ipc import trusted_path
from .model import PolicyError

CLIENT=Path('/Library/PrivilegedHelperTools/local.hotturkey/HotTurkeyPolicyClient')
ROUTES={'state':'snapshot','auth':'authenticate','export':'export','import':'import',
        'categories':'categories','users':'users','settings':'settings','check':'check',
        'statistics':'statistics','statistics/export':'statistics-export','statistics/clear':'statistics-clear',
        **{'blocks/'+name:name for name in ['save','add-targets','reset-pomodoro','delete','toggle','lock','unlock','break','duplicate']}}


class SystemClient:
    def __init__(self,command=None):self.command=command;self.session=''

    def request(self,operation,data=None):
        payload=json.dumps({'op':operation,'data':{} if data is None else data,'session':self.session},ensure_ascii=False,allow_nan=False).encode()
        if len(payload)>MAX_DOCUMENT:raise PolicyError('数据超过 64 MiB，请分批处理')
        try:
            command=[str(trusted_path(CLIENT))] if self.command is None else list(self.command)
            result=subprocess.run(command,input=payload,capture_output=True,timeout=180,env={'PATH':'/usr/bin:/bin'})
        except (OSError,subprocess.TimeoutExpired):raise PolicyError('受保护后台未连接或响应超时') from None
        if result.returncode or len(result.stdout)>MAX_DOCUMENT+16384:raise PolicyError('受保护后台通信失败')
        try:value=json.loads(result.stdout)
        except (ValueError,UnicodeError):raise PolicyError('受保护后台响应无效') from None
        if not isinstance(value,dict) or value.get('ok') is not True:raise PolicyError(value.get('error','请求未通过验证') if isinstance(value,dict) else '响应无效')
        return value.get('result')

    def api(self,path,data=None):
        if path not in ROUTES:raise PolicyError('系统接口操作无效')
        if path=='check' and isinstance(data,dict):
            data={key:value for key,value in data.items() if key!='record'}
        result=self.request(ROUTES[path],data)
        if path=='auth':self.session=result['session']
        return result
