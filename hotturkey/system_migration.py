"""Private SQLite snapshots for protected installation; no service management.

Read user files through no-follow descriptors, copy them into a private area,
then let SQLite interpret only that private copy. Never open a user-controlled
database path with the installer's privileged SQLite connection.
"""
import os
import shutil
import sqlite3
import stat
import tempfile
from pathlib import Path

from .authority import PolicyAuthority
from .engine import Engine
from .ipc import decode_json
from .model import PolicyError
from .store import Store

MAX_DATABASE=2*1024**3
TABLES={'state','events','event_blocks','charges','sqlite_sequence'}


def fingerprint(info):return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def copy_owned_file(source,destination,uid):
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
    descriptor=os.open(source,flags)
    try:
        before=os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=uid or before.st_nlink!=1
                or before.st_mode&0o077 or before.st_size>MAX_DATABASE):raise PermissionError('数据库文件身份、类型或权限无效')
        with os.fdopen(os.dup(descriptor),'rb') as input_stream,Path(destination).open('xb') as output:
            os.fchmod(output.fileno(),0o600);total=0
            while True:
                chunk=input_stream.read(1024*1024)
                if not chunk:break
                total+=len(chunk)
                if total>MAX_DATABASE:raise ValueError('数据库超过允许大小')
                output.write(chunk)
            output.flush();os.fsync(output.fileno())
        if total!=before.st_size or fingerprint(before)!=fingerprint(os.fstat(descriptor)):
            raise RuntimeError('数据库复制期间发生变化，请先停止旧后台')
        return fingerprint(before)
    finally:os.close(descriptor)


def validate_database(connection):
    if connection.execute('PRAGMA quick_check').fetchall()!=[('ok',)]:raise ValueError('数据库完整性检查失败')
    schema=connection.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%'").fetchall()
    if any(kind not in {'table','index'} or kind=='table' and name not in TABLES for kind,name in schema):raise ValueError('数据库包含未知表或可执行结构')
    expected={'state':['id','value'],'events':['id','at','user','kind','target','block_id','seconds','blocked'],
              'event_blocks':['event_id','block_id'],'charges':['at','block_id','seconds']}
    for name,columns in expected.items():
        if [row[1] for row in connection.execute('PRAGMA table_info('+name+')')]!=columns:raise ValueError('数据库结构无效')
    rows=connection.execute('SELECT id,value FROM state').fetchall()
    if len(rows)!=1 or rows[0][0]!=1:raise ValueError('数据库策略记录无效')
    state=decode_json(rows[0][1])
    if not isinstance(state,dict) or state.get('version')!=1 or not isinstance(state.get('blocks'),list):raise ValueError('策略格式无效')
    return state


def snapshot_database(source,destination,uid):
    """Copy a stopped service's DB/WAL without trusting user-selected links."""
    source=Path(source);destination=Path(destination)
    if destination.exists() or destination.is_symlink():raise FileExistsError('数据库目标已存在')
    destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    try:
        rollback_journal=source.with_name(source.name+'-journal')
        if rollback_journal.exists() or rollback_journal.is_symlink():raise ValueError('源数据库仍有回退日志，请先通过旧后台完成恢复并安全停止')
        with tempfile.TemporaryDirectory(prefix='.db-copy-',dir=destination.parent) as temporary:
            private=Path(temporary);copied=private/'hotturkey.sqlite3';observed={}
            for suffix in ['', '-wal']:
                path=source.with_name(source.name+suffix)
                if suffix and not path.exists() and not path.is_symlink():continue
                observed[path]=copy_owned_file(path,Path(str(copied)+suffix),uid)
            # SHM is deliberately regenerated only in this private directory.
            if source.with_name(source.name+'-wal').exists() and source.with_name(source.name+'-wal') not in observed:raise RuntimeError('数据库日志在复制期间发生变化')
            for path,identity in observed.items():
                if fingerprint(path.lstat())!=identity:raise RuntimeError('数据库文件在复制期间被替换')
            if rollback_journal.exists() or rollback_journal.is_symlink():raise RuntimeError('源数据库在复制期间开始写入')
            connection=sqlite3.connect(str(copied),timeout=2)
            try:
                validate_database(connection)
                output=sqlite3.connect(str(destination));destination.chmod(0o600)
                try:connection.backup(output);validate_database(output)
                finally:output.close()
            finally:connection.close()
        return destination
    except BaseException:
        for suffix in ['', '-wal','-shm']:Path(str(destination)+suffix).unlink(missing_ok=True)
        raise


def ensure_database_unlocked(directory,uid,boot_id,resolve_user):
    store=Store(directory)
    try:
        state=store.state
        if 'authority_version' in state:
            authority=PolicyAuthority(store,uid,resolve_user=resolve_user,boot_id=boot_id)
            locked=not authority.can_uninstall()
        else:locked=any(Engine(store,boot_id=boot_id,user=resolve_user(uid).pw_name).locked(block) for block in state['blocks'])
        if locked:raise PolicyError('有规则仍处于锁定状态，不能迁移、更新或卸载系统后台')
    finally:store.db.close()


def migrate_database(source,destination,uid,source_uid,boot_id,resolve_user):
    """Migrate only the private copy. The original database is never modified."""
    destination=Path(destination)
    if destination.exists() or destination.is_symlink():raise FileExistsError('迁移目标目录已存在')
    destination.mkdir(mode=0o700)
    try:
        snapshot_database(source,destination/'hotturkey.sqlite3',source_uid)
        ensure_database_unlocked(destination,uid,boot_id,resolve_user)
        store=Store(destination)
        try:
            authority=PolicyAuthority(store,uid,resolve_user=resolve_user,boot_id=boot_id)
            authority.engine(uid)
            # Leave no copied WAL dependency when this directory is promoted.
            store.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            return {'rules':len(store.state['blocks']),'controller_uid':uid,'authority_version':store.state['authority_version']}
        finally:store.db.close()
    except BaseException:
        shutil.rmtree(destination);raise
