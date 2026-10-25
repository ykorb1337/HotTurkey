"""Test-only launchd program; never packaged in a production application."""
import base64
import dataclasses
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
mode=sys.argv[1];configuration=json.loads(Path(sys.argv[2]).read_text())
sys.path.insert(0,str(ROOT if mode=='legacy' else Path(configuration['program'])/'project'))

if mode=='legacy':
    from hotturkey.server import Service
    service=Service(Path(configuration['legacy']),enforce=True)
    try:service.run()
    finally:service.store.db.close()
elif mode=='authority':
    from hotturkey.authority import PolicyAuthority
    from hotturkey.authority_server import AuthorityServer
    from hotturkey.installation_gate import InstallationGate
    from hotturkey.ipc import peer_identity
    from hotturkey.platform_macos import boot_id
    from hotturkey.service_lease import ServiceLease
    from hotturkey.store import Store
    from hotturkey.system_enforcement import SystemExecution
    from hotturkey.system_package import digest
    from hotturkey.trusted_sessions import TrustedSessions
    uid=os.getuid();data=Path(configuration['database']);gate=InstallationGate(Path(configuration['marker']),uid,digest(Path(configuration['program'])/'payload.json'),owner_uid=uid,anchor=Path(configuration['root']))
    lease=ServiceLease(data/'service.lock');store=Store(data)
    try:
        authority=PolicyAuthority(store,uid,boot_id=boot_id(),installation_gate=gate)
        execution=SystemExecution(authority,ROOT/'build/HotTurkeySystemAgentQA',lease=lease);sessions=TrustedSessions(authority,execution)
        checker=ROOT/'build/HotTurkeyPeerCheck'
        requirements={role:json.loads(subprocess.check_output([str(checker),'--describe',str(ROOT/'build'/binary)]))['requirement']
            for role,binary in [('client','HotTurkeyPolicyClientQA'),('session','HotTurkeySessionAgentQA')]}
        def verify(connection):
            identity=peer_identity(connection)
            result=subprocess.run([str(checker),'--audit',base64.b64encode(identity.audit_token).decode(),'--roles',json.dumps(requirements)],capture_output=True,timeout=3)
            if result.returncode:raise PermissionError('Denied')
            return dataclasses.replace(identity,role=json.loads(result.stdout)['role'])
        server=AuthorityServer(authority,Path(configuration['socket']),verify,execution=execution,sessions=sessions,tick_interval=.1)
        server.bind()
        for number in [signal.SIGTERM,signal.SIGINT]:signal.signal(number,lambda *_:server.stop())
        server.serve_forever()
    finally:store.db.close();lease.close()
else:raise SystemExit(64)
