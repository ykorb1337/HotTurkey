"""Production launchd plan. Rendering it never writes or loads system files."""
from pathlib import Path

INSTALL=Path('/Library/PrivilegedHelperTools/local.hotturkey')
SESSION_PLIST=Path('/Library/LaunchAgents/local.hotturkey.session.plist')


def session_launch_agent():
    return {'Label':'local.hotturkey.session','ProgramArguments':[str(INSTALL/'HotTurkeySessionAgent')],
            'RunAtLoad':True,'KeepAlive':True,'LimitLoadToSessionType':'Aqua',
            'ThrottleInterval':10,'ProcessType':'Interactive','ExitTimeOut':5,
            'AbandonProcessGroup':True,'StandardOutPath':'/dev/null','StandardErrorPath':'/dev/null',
            'EnvironmentVariables':{'PATH':'/usr/bin:/bin'}}
