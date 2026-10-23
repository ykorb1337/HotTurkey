"""Real kernel scanner + signed RPC + isolated application enforcement.

Uses a current-UID-only QA executor. No root installation, installed policy,
user applications, login items, device actions or other accounts are modified.
"""
import base64,copy,json,os,shutil,signal,socket,subprocess,sys,tempfile,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.authority import PolicyAuthority
from hotturkey.authority_server import AuthorityServer
from hotturkey.ipc import peer_identity
from hotturkey.platform_macos import native_samples,native_command,stop_native
from hotturkey.store import Store
from hotturkey.system_enforcement import SystemExecution


def wait_for(check,seconds=10):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        value=check()
        if value:return value
        time.sleep(.1)
    raise TimeoutError('Isolated execution verification timed out')


def main():
    qa=ROOT/'build/HotTurkeySystemAgentQA';production=ROOT/'build/HotTurkeySystemAgent'
    checker=ROOT/'build/HotTurkeyPeerCheck';client=ROOT/'build/HotTurkeyPolicyClientQA'
    approved=json.loads(subprocess.check_output([str(checker),'--describe',str(client)]))['requirement']
    proof={'root_installed':False,'separate_macOS_accounts_tested':False}
    with tempfile.TemporaryDirectory(prefix='ht-system-executor-',dir='/private/tmp') as temporary:
        folder=Path(temporary);fixtures=[];server=None;server_thread=None;store=None
        source=folder/'fixture.c'
        source.write_text('#include <signal.h>\n#include <unistd.h>\n#include <stdio.h>\n#include <string.h>\nvolatile sig_atomic_t go=0;\nvoid advance(int s){go=1;}\nint main(int n,char **v){if(n>1&&strcmp(v[1],"--ignore")==0)signal(SIGTERM,SIG_IGN);if(n>2)signal(SIGUSR1,advance);puts("ready");fflush(stdout);for(;;){if(go&&n>2){execl(v[2],v[2],(char*)0);return 3;}pause();}}\n')
        binary=folder/'fixture'
        subprocess.run(['/usr/bin/clang',str(source),'-o',str(binary)],check=True)
        def launch(name,*args):
            target=folder/name;shutil.copy2(binary,target)
            process=subprocess.Popen([str(target),*args],stdout=subprocess.PIPE)
            fixtures.append(process);assert process.stdout.readline()==b'ready\n'
            return target,process
        def verify(connection):
            identity=peer_identity(connection)
            result=subprocess.run([str(checker),'--audit',base64.b64encode(identity.audit_token).decode(),'--requirement',approved],capture_output=True,text=True,timeout=3)
            if result.returncode or json.loads(result.stdout).get('ok') is not True:raise PermissionError('Denied')
            return identity
        try:
            unrelated_path,unrelated=launch('Unrelated')
            # Low-level native checks: UID, generation/exec identity and whole-frame rejection.
            replacement=folder/'Replacement';shutil.copy2(binary,replacement)
            driver_path,driver=launch('ExecDriver','--exec',str(replacement))
            helper=subprocess.Popen([str(qa)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
            stop=threading.Event();samples=native_samples(helper,stop,lambda:None)
            try:
                initial=next(samples);old=next(p for p in initial['apps'] if p['pid']==driver.pid)
                assert old['uid']==os.getuid() and old['executable']==str(driver_path)
                payload={k:old[k] for k in ['pid','uid','identity']}
                assert native_command(helper,stop,{'kill':[{**payload,'uid':os.getuid()+100}]})
                value=next(samples);assert value['results'][0]['result']=='stale' and driver.poll() is None
                assert native_command(helper,stop,{'kill':[{**payload,'identity':'0'*64}]})
                value=next(samples);assert value['results'][0]['result']=='stale' and driver.poll() is None
                os.kill(driver.pid,signal.SIGUSR1);assert driver.stdout.readline()==b'ready\n'
                assert native_command(helper,stop,{'kill':[payload]})
                value=next(samples);changed=next(p for p in value['apps'] if p['pid']==driver.pid)
                assert changed['identity']!=old['identity'] and changed['executable']==str(replacement)
                assert value['results'][0]['result']=='stale' and driver.poll() is None
                # A valid first action followed by malformed data must signal neither.
                valid={k:changed[k] for k in ['pid','uid','identity']}
                assert native_command(helper,stop,{'kill':[valid,{**valid,'pid':True}]})
                assert helper.wait(timeout=4)==65 and driver.poll() is None
                proof.update(real_kernel_uid_pid=True,wrong_uid_and_generation_rejected=True,same_pid_exec_change_rejected=True,malformed_batch_has_no_partial_signals=True)
            finally:stop.set();stop_native(helper)
            if os.getuid()!=0:
                refusal=subprocess.run([str(production)],input=b'',capture_output=True,timeout=3)
                assert refusal.returncode==77
                proof['production_executor_refuses_unprivileged_launch']=True
            data_dir=folder/'data';path=folder/'socket'
            def start():
                nonlocal server,server_thread,store
                store=Store(data_dir);authority=PolicyAuthority(store,os.getuid(),boot_id='system-execution-fixture')
                execution=SystemExecution(authority,qa,protected_paths=[ROOT])
                server=AuthorityServer(authority,path,verify,execution=execution,tick_interval=.2)
                server.bind();errors=[]
                def run():
                    try:server.serve_forever()
                    except Exception as e:errors.append(str(e))
                server_thread=threading.Thread(target=run);server_thread.start()
                return authority,execution,errors
            def call(op,data=None):
                value=subprocess.run([str(client),str(path),str(os.getuid())],input=json.dumps({'op':op,'data':data or {}}).encode(),capture_output=True,timeout=8,check=True)
                result=json.loads(value.stdout);assert result['ok'],result
                return result['result']
            def finish():
                nonlocal server,server_thread,store
                if server:
                    server.stop();server_thread.join(timeout=12);assert not server_thread.is_alive();server=None
                if store:store.db.close();store=None
            authority,execution,errors=start()
            game_path,game=launch('Game '+chr(0x6e38)+chr(0x620f)+' \"fixture\"');stubborn_path,stubborn=launch('Stubborn','--ignore')
            block=call('save',{'block':{'name':'Isolated system target','enabled':True,'applications':[]}})
            locked=call('lock',{'id':block['id'],'type':'timer','until':authority.engine(os.getuid()).now()+600})
            before=copy.deepcopy(locked['lock']);started=authority.engine(os.getuid()).runtime(locked)['started']
            for operation,rejected_data in [('kill',{'pid':unrelated.pid}),('usage',{'uid':os.getuid(),'seconds':100000}),('process-sample',{'apps':[]})]:
                response=subprocess.run([str(client),str(path),str(os.getuid())],input=json.dumps({'op':operation,'data':rejected_data}).encode(),capture_output=True,timeout=8,check=True)
                assert not json.loads(response.stdout)['ok'] and unrelated.poll() is None
            proof['RPC_rejects_direct_pid_commands_and_client_usage']=True
            added=call('add-targets',{'id':block['id'],'applications':['binary:'+str(game_path)]})
            assert added['lock']==before
            wait_for(lambda:game.poll() is not None);assert game.returncode==-signal.SIGTERM
            assert unrelated.poll() is None and driver.poll() is None and stubborn.poll() is None
            call('add-targets',{'id':block['id'],'applications':['binary:'+str(stubborn_path)]})
            wait_for(lambda:stubborn.poll() is not None);assert stubborn.returncode==-signal.SIGKILL
            wait_for(lambda:store.statistics()['totals']['blocked']>=2)
            assert authority.engine(os.getuid()).runtime(locked)['started']==started
            assert call('snapshot')['system_execution']['status']=='running' and not errors
            proof.update(signed_RPC_policy_drives_real_executor=True,locked_append_enforced=True,SIGTERM_then_SIGKILL_verified=True,unrelated_processes_preserved=True,confirmed_kills_recorded=True,original_lock_and_start_preserved=True)
            assert execution.process is not None
            execution.process.kill()
            server_thread.join(timeout=12)
            assert not server_thread.is_alive() and errors==['Protected process enforcement failed']
            proof['executor_failure_stops_authority_for_supervisor_recovery']=True
            finish();assert not path.exists()
            # Persisted policy and lock are used by a fresh scanner after restart.
            authority,execution,errors=start()
            restarted=subprocess.Popen([str(game_path)],stdout=subprocess.PIPE);fixtures.append(restarted);assert restarted.stdout.readline()==b'ready\n'
            wait_for(lambda:restarted.poll() is not None);assert restarted.returncode==-signal.SIGTERM
            assert call('snapshot')['blocks'][0]['lock']==before and not errors
            proof['restart_recovers_enforcement_with_lock_preserved']=True
            finish();proof['bounded_shutdown_and_socket_cleanup']=True
            assert unrelated.poll() is None and driver.poll() is None
        finally:
            if server:server.stop();server_thread.join(timeout=12)
            if store:store.db.close()
            for process in fixtures:
                if process.poll() is None:process.kill()
                process.wait(timeout=4)
                if process.stdout:process.stdout.close()
    (ROOT/'build/system-execution-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
