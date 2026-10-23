"""Bounded, expiring document transfers bound to a kernel peer incarnation.

Protected callers hold the authority store lock; the current-user host is
single-threaded. Chunks never execute an operation;
uploads are verified and parsed in full before dispatching any policy change.
"""
import base64
import hashlib
import json
import os
import secrets

from .model import PolicyError

MAX_DOCUMENT=64*1024*1024
MAX_TOTAL=128*1024*1024
INLINE_LIMIT=512*1024
CHUNK=256*1024
LIFETIME=120
MARKER='__hotturkey_document__'


def encode(value):
    result=bytearray()
    for part in json.JSONEncoder(ensure_ascii=False,separators=(',',':'),allow_nan=False).iterencode(value):
        piece=part.encode()
        if len(result)+len(piece)>MAX_DOCUMENT:raise PolicyError('数据超过 64 MiB，请分批处理')
        result.extend(piece)
    return bytes(result)


class Documents:
    def __init__(self,clock):self.clock=clock;self.records={}

    @staticmethod
    def owner(identity):
        # None is only the unprivileged, process-local Native Messaging cache.
        # Protected RPC always supplies a verified kernel peer, never None.
        if identity is None:return ('local-host',os.getpid())
        return (identity.uid,identity.role,identity.pid,identity.audit_token)

    def prune(self):
        now=self.clock()
        self.records={key:value for key,value in self.records.items() if value['until']>now}

    def reserve(self,identity,size,operation,session,mode):
        self.prune()
        if type(size) is not int or not 0<size<=MAX_DOCUMENT:raise PolicyError('数据大小无效')
        if sum(value['size'] for value in self.records.values())+size>MAX_TOTAL:raise PolicyError('传输繁忙，请稍后重试')
        owner=self.owner(identity)
        if sum(value['owner'][0]==owner[0] for value in self.records.values())>=4:raise PolicyError('传输数量过多')
        token=secrets.token_urlsafe(32)
        self.records[token]={'owner':owner,'until':self.clock()+LIFETIME,'size':size,
                             'operation':operation,'session':session,'mode':mode,'next':0}
        return token,self.records[token]

    def record(self,identity,token,mode):
        self.prune()
        if not isinstance(token,str) or len(token)>128:raise PolicyError('传输标识无效')
        record=self.records.get(token)
        if record is None or record['owner']!=self.owner(identity) or record['mode']!=mode:raise PolicyError('传输已过期或身份不符')
        return record

    def pack(self,identity,operation,session,value):
        self.prune()
        encoded=encode(value)
        if len(encoded)<=INLINE_LIMIT:return value
        token,record=self.reserve(identity,len(encoded),operation,session,'read')
        record.update(data=encoded,sha256=hashlib.sha256(encoded).hexdigest())
        return self.page(identity,token,0)

    def page(self,identity,token,offset):
        record=self.record(identity,token,'read')
        if type(offset) is not int or offset!=record['next']:raise PolicyError('传输页顺序无效')
        end=min(offset+CHUNK,record['size']);record['next']=end
        result={MARKER:{'id':token,'size':record['size'],'sha256':record['sha256']},'offset':offset,
                'data':base64.b64encode(record['data'][offset:end]).decode(),'next':end if end<record['size'] else None}
        if end==record['size']:del self.records[token]
        return result

    def start(self,identity,operation,session,size,digest):
        if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):raise PolicyError('数据校验值无效')
        token,record=self.reserve(identity,size,operation,session,'write')
        record.update(data=bytearray(),sha256=digest)
        return {'id':token,'chunk_size':CHUNK}

    def append(self,identity,token,offset,data):
        record=self.record(identity,token,'write')
        if type(offset) is not int or offset!=record['next'] or not isinstance(data,str) or len(data)>4*((CHUNK+2)//3):raise PolicyError('上传片段无效')
        try:piece=base64.b64decode(data,validate=True)
        except ValueError:raise PolicyError('上传编码无效') from None
        if not piece or len(piece)>CHUNK or offset+len(piece)>record['size']:raise PolicyError('上传大小无效')
        record['data'].extend(piece);record['next']+=len(piece)
        return {'next':record['next']}

    def finish(self,identity,token):
        record=self.record(identity,token,'write')
        del self.records[token]
        if record['next']!=record['size'] or hashlib.sha256(record['data']).hexdigest()!=record['sha256']:raise PolicyError('上传不完整或校验失败')
        from .ipc import decode_json
        try:
            value=decode_json(record['data'])
        except (ValueError,UnicodeError,RecursionError):raise PolicyError('上传内容无效') from None
        if not isinstance(value,dict) or value.get('op')!=record['operation'] or value.get('session','')!=record['session']:raise PolicyError('上传操作不符')
        return value
