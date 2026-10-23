"""Browser Native Messaging framing. Only policy/usage operations are exposed."""
import json
import os
import struct
import sys
import time
import urllib.request
import urllib.error
from .server import default_data
from .documents import Documents,MAX_DOCUMENT
from .model import PolicyError
from .ipc import decode_json

def read_exact(stream,count):
    data=bytearray()
    while len(data)<count:
        part=stream.read(count-len(data))
        if not part: return None
        data.extend(part)
    return bytes(data)

def main():
    documents=Documents(time.monotonic)
    while True:
        header=read_exact(sys.stdin.buffer,4)
        if header is None: return
        size=struct.unpack("<I",header)[0]
        if not 0<size<=MAX_DOCUMENT: return
        payload=read_exact(sys.stdin.buffer,size)
        if payload is None: return
        try:
            message=decode_json(payload)
            if message.get('op')=='document-read':
                data=message.get('data',{})
                if not isinstance(data,dict) or set(data)!={'id','offset'}:raise ValueError('Invalid document page')
                result=documents.page(None,data['id'],data['offset'])
                encoded=json.dumps(result,ensure_ascii=False).encode()
                sys.stdout.buffer.write(struct.pack('<I',len(encoded))+encoded);sys.stdout.buffer.flush()
                continue
            path={"check":"/api/check","sync":"/api/bridge","break":"/api/extension/break","closed-tab":"/api/extension/closed-tab",'tab-unblock':'/api/extension/tab-unblock','tab-close':'/api/extension/tab-close','add-site-options':'/api/extension/add-site-options','add-site':'/api/extension/add-site'}.get(message.get("op"))
            # The popup may only append a validated website; no general edits/unlocks.
            if path is None: raise ValueError("Unsupported operation")
            connection=json.loads((default_data()/"connection.json").read_text())
            request=urllib.request.Request(f'http://127.0.0.1:{connection["port"]}{path}',data=json.dumps(message.get("data",{})).encode(),headers={"Authorization":"Bearer "+connection["token"],"Content-Type":"application/json"})
            with urllib.request.urlopen(request,timeout=5) as response: result=json.load(response)
            if message.get('document_protocol')==1:result=documents.pack(None,message['op'],'',result)
        except PolicyError as exc:
            result={'error':str(exc),'policy':True}
        except urllib.error.HTTPError as exc:
            try:result={'error':json.load(exc).get('error','请求未通过验证'),'policy':True}
            except (ValueError,AttributeError):result={'error':'请求未通过验证','policy':True}
        except Exception as exc:
            result={"error":"HotTurkey 后台未连接","detail":type(exc).__name__}
        encoded=json.dumps(result,ensure_ascii=False).encode()
        if len(encoded)>1024*1024:
            encoded=json.dumps({'error':'规则列表较大，请重新加载 HotTurkey 扩展以更新通信协议','policy':True},ensure_ascii=False).encode()
        sys.stdout.buffer.write(struct.pack("<I",len(encoded))+encoded)
        sys.stdout.buffer.flush()

if __name__=="__main__": main()
