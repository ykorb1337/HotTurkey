"""Real disposable launchd groups: registration removal is not exit evidence.

The only signals target random QA jobs, or the fixture child deliberately
created to survive its job. No production registration, user app or rule is
modified. Production root execution remains outside this test's scope.
"""
import json
import os
import plistlib
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.system_jobs import _Job,_JobControl,read_plan
from hotturkey.system_processes import JobProcesses,KernelProcesses

SOURCE=r'''
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
int main(int argc,char **argv){
 if(argc!=4)return 64;
 pid_t child=fork();if(child<0)return 1;
 if(child==0){if(atoi(argv[1])){if(setsid()<0)return 2;signal(SIGTERM,SIG_IGN);}for(;;)sleep(1);}
 usleep(100000);FILE *pid=fopen(argv[2],"w");if(!pid)return 3;fprintf(pid,"%d\n",child);fclose(pid);
 for(;;){FILE *beat=fopen(argv[3],"a");if(!beat)return 4;fputs("beat\n",beat);fclose(beat);usleep(100000);}
}
'''


def main():
    domain='gui/'+str(os.getuid());kernel=KernelProcesses();proof={'root_installed':False,'production_service_driver_tested':False,'installed_rules_changed':False,'physical_sleep_invoked':False}
    proof['gui_domain_available']=_JobControl(lambda:None,lambda job:None).domain_exists(domain)
    if not proof['gui_domain_available']:
        proof['native_job_exit_exercised']=False
        (ROOT/'build/job-exit-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof));return
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-job-exit-') as temporary:
        root=Path(temporary);source=root/'fixture.c';source.write_text(SOURCE);binary=root/'owned-exit-fixture'
        subprocess.run(['/usr/bin/clang',str(source),'-o',str(binary)],check=True,capture_output=True)
        for mode in ['normal','surviving-child','proof-failure']:
            case=root/mode;case.mkdir(mode=0o700);label='local.hotturkey.exit.qa.'+uuid.uuid4().hex;pidfile=case/'child';beat=case/'heartbeat'
            plan={'Label':label,'ProgramArguments':[str(binary),'1' if mode=='surviving-child' else '0',str(pidfile),str(beat)],
                'RunAtLoad':True,'KeepAlive':False,'ExitTimeOut':1,'StandardOutPath':'/dev/null','StandardErrorPath':'/dev/null'}
            plist=case/'job.plist';plist.write_bytes(plistlib.dumps(plan));job=_Job(domain,label,plist,plan)
            control=_JobControl(lambda:None,lambda value:read_plan(value.plist,value.expected,owner_uid=os.getuid(),anchor=case),timeout=4)
            child=None;identity=None
            try:
                assert control.load(job)
                until=time.monotonic()+10
                while not pidfile.exists() and time.monotonic()<until:time.sleep(.05)
                assert pidfile.exists();child=int(pidfile.read_text());identity=kernel.process(child);assert identity is not None and identity.uid==os.getuid()
                if mode=='proof-failure':
                    before=beat.stat().st_size
                    def failed(pid,uid):raise RuntimeError('Injected proof failure')
                    try:control.pause_unload(job,observe=failed)
                    except RuntimeError:pass
                    else:raise AssertionError('Expected proof failure')
                    until=time.monotonic()+3
                    while beat.stat().st_size<=before and time.monotonic()<until:time.sleep(.05)
                    assert beat.stat().st_size>before,'Failed handoff left old job frozen'
                    assert control.loaded(job);proof['failed_proof_resumes_real_old_job']=True
                else:
                    recorded=[];handoff_ready=False
                    try:
                        control.pause_unload(job,before_unload=lambda observer:recorded.append(sorted(observer.groups)))
                        handoff_ready=True
                    except TimeoutError:
                        assert mode=='surviving-child'
                    assert recorded
                    if mode=='normal':
                        assert handoff_ready and not control.loaded(job)
                        assert kernel.process(child) is None or not kernel.process(child).live
                        proof['real_group_exit_required_before_handoff']=True
                    else:
                        assert not handoff_ready and not control.loaded(job)
                        current=kernel.process(child);assert current is not None and current.identity==identity.identity and current.live
                        proof['orphan_in_separate_group_blocks_handoff']=True
            finally:
                # This is the test's exact unique label, never a whole domain.
                subprocess.run(['/bin/launchctl','bootout',job.target],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
                if child is not None:
                    current=kernel.process(child)
                    if current is not None and current.live and current.identity==identity.identity:os.kill(child,signal.SIGKILL)
            assert not control.loaded(job)
    proof['native_job_exit_exercised']=True
    (ROOT/'build/job-exit-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
