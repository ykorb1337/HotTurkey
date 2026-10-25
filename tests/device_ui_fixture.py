"""Disposable browser UI fixture. Enforcement is always disabled."""
import datetime as dt
import argparse
import json
import sys
import tempfile
import threading
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hotturkey.engine import Engine
from hotturkey.server import Service


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--configured',action='store_true');args=parser.parse_args()
    with tempfile.TemporaryDirectory(dir='/private/tmp',prefix='ht-device-ui-') as temporary:
        service=Service(temporary,enforce=False)
        now=dt.datetime.now().replace(hour=12,minute=0,second=0,microsecond=0).timestamp()
        service.engine=Engine(service.store,wall=lambda:now,user='Isolated device QA')
        if args.configured:
            # Public fictional credential, confined to a disposable model-only service.
            service.engine.configure_device_recovery('fixture-safe-word')
            service.engine.save_block({'name':'Isolated recovery check','device':'sleep','mode':'scheduled','enabled':True,'confirm_device':True,
                'schedule':[{'days':list(range(7)),'start':660,'end':780}]})
        thread=threading.Thread(target=service.http.serve_forever);thread.start()
        record={'url':service.origin+'/#token='+service.token,'enforcement':False,'installed_rules_changed':False}
        (ROOT/'build/device-ui-fixture.json').write_text(json.dumps(record))
        print('Isolated device UI ready; enforcement disabled. Press Enter to finish.',flush=True)
        try:input()
        finally:
            service.http.shutdown();service.http.server_close();thread.join(timeout=5)
            service.store.db.close();service.singleton.close()


if __name__=='__main__':main()
