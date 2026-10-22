"""Browser Native Messaging framing. Only policy/usage operations are exposed."""
import json
import os
import struct
import sys
import urllib.request
from .server import default_data

def read_exact(stream,count):
    data=b""
    while len(data)<count:
        part=stream.read(count-len(data))
        if not part: return None
        data+=part
    return data

def main():
    while True:
        header=read_exact(sys.stdin.buffer,4)
        if header is None: return
        size=struct.unpack("<I",header)[0]
        if size>1024*1024: return
        payload=read_exact(sys.stdin.buffer,size)
        if payload is None: return
        try:
            message=json.loads(payload)
            path={"check":"/api/check","sync":"/api/bridge","break":"/api/blocks/break","closed-tab":"/api/extension/closed-tab"}.get(message.get("op"))
            # Browser content must never be able to mutate blocks/settings or unlock.
            if path is None: raise ValueError("Unsupported operation")
            if message.get("op")=="break": path="/api/extension/break"
            connection=json.loads((default_data()/"connection.json").read_text())
            request=urllib.request.Request(f'http://127.0.0.1:{connection["port"]}{path}',data=json.dumps(message.get("data",{})).encode(),headers={"Authorization":"Bearer "+connection["token"],"Content-Type":"application/json"})
            with urllib.request.urlopen(request,timeout=5) as response: result=json.load(response)
        except Exception as exc:
            result={"error":"HotTurkey 后台未连接","detail":type(exc).__name__}
        encoded=json.dumps(result,ensure_ascii=False).encode()
        sys.stdout.buffer.write(struct.pack("<I",len(encoded))+encoded)
        sys.stdout.buffer.flush()

if __name__=="__main__": main()
