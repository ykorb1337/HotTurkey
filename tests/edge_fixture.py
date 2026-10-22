"""Drive only the named QA rule through the public API for real Edge UI testing."""
import json
import sys
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
data=Path.home()/'Library/Application Support/HotTurkey'
info=json.loads((data/'connection.json').read_text())
def call(path,value=None):
    req=urllib.request.Request(f'http://127.0.0.1:{info["port"]}/api/'+path,data=json.dumps(value).encode() if value is not None else None,headers={'Authorization':'Bearer '+info['token'],'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=10) as response:return json.load(response)
path=ROOT/'build/edge-fixture.json'
command=sys.argv[1]
if command=='create':
    state=call('state')
    if path.exists():raise SystemExit('QA fixture already exists; clean up first')
    block=call('blocks/save',{'block':{'name':'QA · Edge 浏览器验证','enabled':True,'websites':['example.com'],'exceptions':['example.com/learn']}})
    path.write_text(json.dumps({'id':block['id'],'block_inactive':state['settings']['block_inactive']}))
    call('settings',{'block_inactive':True})
    print('Created test rule for example.com; /learn is allowed.')
elif command=='cleanup':
    fixture=json.loads(path.read_text());call('blocks/delete',{'id':fixture['id']});call('settings',{k:fixture[k] for k in ['block_inactive','strict_usage'] if k in fixture});path.unlink();print('Removed QA browser rule and restored settings.')
elif command in {'allowance','block','text','network'}:
    fixture=json.loads(path.read_text());block=next(b for b in call('state')['blocks'] if b['id']==fixture['id'])
    block['break']={'allowance':{'type':'allowance','allowance_minutes':1},'block':{'type':'none'},'network':{'type':'none'},'text':{'type':'text','custom_text':'focus','break_minutes':1}}[command]
    if command=='network':block['exceptions']=[]
    call('blocks/save',{'id':block['id'],'block':block});print('Updated QA rule:',command)
    if command=='allowance':
        fixture['strict_usage']=call('state')['settings']['strict_usage'];path.write_text(json.dumps(fixture));call('settings',{'strict_usage':True})
elif command=='check':
    for url in ['https://example.com/','https://example.com/learn']:
        value=call('check',{'url':url,'record':False});print(url,'BLOCKED' if value['blocked'] else 'ALLOWED')
elif command=='bridge':
    s=call('state');print(json.dumps({'extensions':s['extensions'],'enforcement':s['enforcement']}))
elif command=='events':
    fixture=json.loads(path.read_text());result=call('statistics?block='+fixture['id']);print(json.dumps(result))
