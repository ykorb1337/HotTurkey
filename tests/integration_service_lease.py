"""Real native executors retain the handoff lock after the parent closes it.

Only empty disposable policies are used. No installed rules are opened, no
device surface is requested, and the system executor is the no-sleep QA build.
"""
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.authority import PolicyAuthority
from hotturkey.server import Service
from hotturkey.service_lease import ServiceLease
from hotturkey.store import Store
from hotturkey.system_enforcement import SystemExecution


def main():
    proof={'root_installed':False,'installed_rules_changed':False,'physical_sleep_invoked':False}
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-lease-') as temporary:
        root=Path(temporary)
        service=Service(root/'legacy',enforce=True);thread=threading.Thread(target=service.run);thread.start()
        try:
            deadline=time.monotonic()+15
            while service.desktop_at==0 and time.monotonic()<deadline:time.sleep(.05)
            assert service.desktop_at>0
            with ServiceLease(root/'legacy/service.lock',create=False) as probe:
                service.service_lease.close();assert not probe.try_acquire(),'Legacy native executor dropped inherited lease'
                service.stop.set();service.http.shutdown();thread.join(timeout=10);assert not thread.is_alive()
                assert probe.try_acquire()
                proof['real_legacy_executor_retains_lease_without_parent_descriptor']=True
        finally:
            service.stop.set()
            if thread.is_alive():service.http.shutdown();thread.join(timeout=10)
            service.store.db.close()
        data=root/'protected';store=Store(data);store.state['settings']['statistics']=False
        lease=ServiceLease(data/'service.lock');authority=PolicyAuthority(store,os.getuid());execution=SystemExecution(authority,ROOT/'build/HotTurkeySystemAgentQA',lease=lease)
        stop=threading.Event();errors=[]
        def run():
            try:execution.run(stop)
            except BaseException as error:errors.append(type(error).__name__)
        thread=threading.Thread(target=run);thread.start()
        try:
            deadline=time.monotonic()+15
            while execution.last_sample is None and time.monotonic()<deadline:time.sleep(.05)
            assert execution.last_sample is not None,errors
            with ServiceLease(data/'service.lock',create=False) as probe:
                lease.close();assert not probe.try_acquire(),'Protected native executor dropped inherited lease'
                stop.set();thread.join(timeout=10);assert not thread.is_alive();assert not errors,errors
                assert probe.try_acquire()
                proof['real_system_executor_retains_lease_without_parent_descriptor']=True
        finally:
            stop.set();thread.join(timeout=10);lease.close();store.db.close()
    (ROOT/'build/service-lease-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
