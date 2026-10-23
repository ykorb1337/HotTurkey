"""Bounded local framing and kernel-attested Darwin peer identity.

UID, PID and audit token are obtained from the connected socket, never JSON.
No listener is installed or opened by importing this module.
"""
import ctypes
import base64
import dataclasses
import json
import math
import os
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

MAX_FRAME=1024*1024
FRAME_TIMEOUT=5
# sys/un.h in the macOS SDK: SOL_LOCAL, LOCAL_PEERPID, LOCAL_PEERTOKEN.
SOL_LOCAL=0
LOCAL_PEERPID=0x002
LOCAL_PEERTOKEN=0x006


class ProtocolError(ValueError):pass


@dataclasses.dataclass(frozen=True)
class PeerIdentity:
    uid:int
    gid:int
    pid:int
    audit_token:bytes
    role:str='client'


def peer_identity(connection):
    if sys.platform!='darwin':raise OSError('Darwin peer identity requires macOS')
    uid=ctypes.c_uint();gid=ctypes.c_uint()
    libc=ctypes.CDLL(None,use_errno=True)
    getpeereid=libc.getpeereid
    getpeereid.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.c_uint)]
    getpeereid.restype=ctypes.c_int
    if getpeereid(connection.fileno(),ctypes.byref(uid),ctypes.byref(gid))!=0:
        error=ctypes.get_errno()
        raise OSError(error,os.strerror(error))
    pid=struct.unpack('=i',connection.getsockopt(SOL_LOCAL,LOCAL_PEERPID,4))[0]
    token=connection.getsockopt(SOL_LOCAL,LOCAL_PEERTOKEN,32)
    if pid<=0 or len(token)!=32:raise ProtocolError('Invalid kernel peer identity')
    return PeerIdentity(uid.value,gid.value,pid,token)


def _read(connection, size, deadline, eof_ok=False):
    result=bytearray()
    while len(result)<size:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('IPC frame timed out')
        connection.settimeout(remaining)
        try:part=connection.recv(size-len(result))
        except socket.timeout:raise TimeoutError('IPC frame timed out') from None
        if not part:
            if eof_ok and not result:return None
            raise ProtocolError('Truncated IPC frame')
        result.extend(part)
    return result


def _reject_constant(value):raise ProtocolError('Non-finite JSON number')


def _float(value):
    result=float(value)
    if not math.isfinite(result):raise ProtocolError('Non-finite JSON number')
    return result


def _integer(value):
    if len(value)>64:raise ProtocolError('Oversized JSON integer')
    return int(value)


def _object(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ProtocolError('Duplicate JSON key')
        value[key]=item
    return value


def receive(connection):
    deadline=time.monotonic()+FRAME_TIMEOUT
    header=_read(connection,4,deadline,eof_ok=True)
    if header is None:return None
    size=struct.unpack('!I',header)[0]
    if not 0<size<=MAX_FRAME:raise ProtocolError('Invalid IPC frame length')
    payload=_read(connection,size,deadline)
    try:value=json.loads(payload,parse_constant=_reject_constant,parse_float=_float,
                         parse_int=_integer,object_pairs_hook=_object)
    except (ValueError,UnicodeError,RecursionError) as exc:raise ProtocolError('Invalid IPC JSON') from exc
    if not isinstance(value,dict):raise ProtocolError('IPC message must be an object')
    return value


def send(connection, value):
    if not isinstance(value,dict):raise ProtocolError('IPC message must be an object')
    payload=json.dumps(value,ensure_ascii=False,allow_nan=False).encode()
    if not 0<len(payload)<=MAX_FRAME:raise ProtocolError('Invalid IPC frame length')
    connection.settimeout(FRAME_TIMEOUT)
    connection.sendall(struct.pack('!I',len(payload))+payload)


def trusted_path(path, owner_uid=0):
    """Reject links and writable ancestors before using a privileged executable."""
    path=Path(os.path.abspath(path))
    for current in [path,*path.parents]:
        info=current.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=owner_uid or info.st_mode&0o022:
            raise PermissionError('Untrusted owner, link or writable path: '+str(current))
        if current!=path and not stat.S_ISDIR(info.st_mode):raise PermissionError('Invalid executable ancestor')
    if not stat.S_ISREG(path.stat().st_mode):raise PermissionError('Expected a regular executable')
    return path


def trusted_directory(path, owner_uid=0):
    path=Path(os.path.abspath(path))
    for current in [path,*path.parents]:
        info=current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid!=owner_uid or info.st_mode&0o022):
            raise PermissionError('Untrusted directory: '+str(current))
    return path


def authenticated_peer(connection, checker, requirement):
    """Use only a server-selected requirement and a protected verifier binary."""
    identity=peer_identity(connection)
    executable=trusted_path(checker)
    result=subprocess.run([str(executable),'--audit',base64.b64encode(identity.audit_token).decode(),
                           '--requirement',requirement],capture_output=True,text=True,timeout=3,
                          env={'PATH':'/usr/bin:/bin'})
    try:valid=result.returncode==0 and json.loads(result.stdout).get('ok') is True
    except (ValueError,AttributeError):valid=False
    if not valid:raise PermissionError('Peer code identity was not approved')
    return identity


def authenticated_roles(connection,checker,requirements):
    """The protected configuration selects roles, never the caller's JSON."""
    if not {'client','session'}<=set(requirements)<={'client','session','browser'} or len(set(requirements.values()))!=len(requirements):
        raise ValueError('Distinct native role requirements are required')
    identity=peer_identity(connection)
    executable=trusted_path(checker)
    result=subprocess.run([str(executable),'--audit',base64.b64encode(identity.audit_token).decode(),
                           '--roles',json.dumps(requirements)],capture_output=True,text=True,timeout=3,
                          env={'PATH':'/usr/bin:/bin'})
    try:
        value=json.loads(result.stdout)
        valid=result.returncode==0 and value.get('ok') is True and value.get('role') in requirements
    except (ValueError,AttributeError):valid=False
    if not valid:raise PermissionError('Peer code role was not approved')
    return dataclasses.replace(identity,role=value['role'])
