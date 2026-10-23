"""Current-user Native Messaging large-policy compatibility, no installed data."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.server import Service


def main():
    node=os.environ.get('HOTTURKEY_TEST_NODE') or shutil.which('node')
    assert node,'Set HOTTURKEY_TEST_NODE to a Node.js executable'
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-local-docs-') as temporary:
        service=Service(temporary)
        service.engine.save_block({'name':'Large browser transport','enabled':True,
            'websites':[f'https://bulk.invalid/{i}/'+'星'*110 for i in range(4000)]})
        thread=threading.Thread(target=service.http.serve_forever);thread.start()
        try:
            result=subprocess.run([node,str(ROOT/'tests/native_browser_documents.cjs'),'--legacy',sys.executable],
                cwd=ROOT,env={**os.environ,'HOTTURKEY_DATA':temporary},capture_output=True,text=True,timeout=45)
            assert result.returncode==0,result.stderr
            proof=json.loads(result.stdout);assert proof['large_browser_policy_JS_decoder'] and proof['all_native_frames_bounded']
            proof.update(current_user_native_messaging=True,isolated_service=True,real_browser_tested=False,installed_rules_changed=False)
        finally:
            service.http.shutdown();thread.join(timeout=5);service.http.server_close();service.store.db.close();service.singleton.close()
            assert not thread.is_alive()
    (ROOT/'build/current-user-document-proof.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))


if __name__=='__main__':main()
