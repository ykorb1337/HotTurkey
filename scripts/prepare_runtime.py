#!/usr/bin/env python3
"""Fetch a pinned, checksummed standalone Python and its upstream license texts."""
import argparse
import hashlib
import json
import os
import platform
import posixpath
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path,PurePosixPath

ROOT=Path(__file__).resolve().parent.parent
CACHE=ROOT/'build/python-runtime'


def target_triple(machine=None):
    machine=machine or platform.machine()
    try:return {'arm64':'aarch64-apple-darwin','aarch64':'aarch64-apple-darwin','x86_64':'x86_64-apple-darwin'}[machine]
    except KeyError:raise ValueError('不支持此处理器架构：'+machine) from None


def checksum(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()


def verified_download(asset,path):
    path=Path(path)
    if path.exists() and path.stat().st_size==asset['size'] and checksum(path)==asset['sha256']:return
    if not asset['url'].startswith('https://github.com/astral-sh/python-build-standalone/releases/download/'):
        raise ValueError('运行时来源不是固定的官方发布地址')
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix(path.suffix+'.partial')
    try:
        with urllib.request.urlopen(asset['url'],timeout=30) as response,temp.open('wb') as output:
            total=0
            while True:
                chunk=response.read(1024*1024)
                if not chunk:break
                total+=len(chunk)
                if total>asset['size'] or total>256*1024*1024:raise ValueError('运行时下载超过预期大小')
                output.write(chunk)
        if total!=asset['size'] or checksum(temp)!=asset['sha256']:raise ValueError('运行时 SHA-256 校验失败')
        temp.replace(path)
    finally:temp.unlink(missing_ok=True)


def checked_members(archive):
    members=archive.getmembers()
    if len(members)>30000 or sum(m.size for m in members)>1024*1024*1024:raise ValueError('运行时归档过大')
    names={m.name:m for m in members}
    if len(names)!=len(members):raise ValueError('运行时归档包含重复路径')
    links={m.name for m in members if m.issym() or m.islnk()}
    for member in members:
        path=PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0]!='python':raise ValueError('运行时归档路径无效')
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()) or member.mode&0o7000:raise ValueError('运行时归档文件类型无效')
        if any(str(parent) in links for parent in path.parents):raise ValueError('运行时归档目录不能是链接')
        if member.issym() or member.islnk():
            target=member.linkname
            if target.startswith('/'):raise ValueError('运行时归档包含绝对链接')
            resolved=posixpath.normpath(posixpath.join(str(path.parent),target) if member.issym() else target)
            if resolved!='python' and not resolved.startswith('python/'):raise ValueError('运行时归档链接越界')
            if member.islnk() and (resolved not in names or not names[resolved].isfile()):raise ValueError('运行时硬链接目标无效')
    return members


def license_metadata(archive,destination):
    destination.mkdir()
    # Only read named files to stdout; never extract the full build archive.
    def read(name):return subprocess.check_output(['/usr/bin/tar','-xOf',str(archive),name],timeout=30)
    metadata=json.loads(read('python/PYTHON.json'))
    paths=set();todo=[metadata]
    while todo:
        item=todo.pop()
        if isinstance(item,dict):
            for key,value in item.items():
                if key=='license_path' and isinstance(value,str):paths.add(value)
                if key=='license_paths' and isinstance(value,list):paths.update(value)
                todo.append(value)
        elif isinstance(item,list):todo.extend(item)
    for path in sorted(paths):
        if not isinstance(path,str) or not path.startswith('licenses/') or PurePosixPath(path).name!=path[9:]:raise ValueError('许可证路径无效')
        (destination/PurePosixPath(path).name).write_bytes(read('python/'+path))
    (destination/'PYTHON.json').write_text(json.dumps(metadata,indent=2)+'\n')
    return len(paths)


def prepare(target=None):
    target=target or target_triple()
    lock=json.loads((ROOT/'runtime/python.lock.json').read_text())
    asset=lock['assets'][target]
    destination=CACHE/target
    marker=destination/'provenance.json'
    expected={'provider':lock['provider'],'release':lock['release'],'python_version':lock['python_version'],'target':target,'archive':asset}
    if marker.exists() and json.loads(marker.read_text())==expected and (destination/'python/bin/python3').exists():return destination
    CACHE.mkdir(parents=True,exist_ok=True)
    archive=CACHE/(target+'.tar.gz');licenses=CACHE/(target+'-licenses.tar.zst')
    verified_download(asset,archive);verified_download(asset['license_archive'],licenses)
    with tempfile.TemporaryDirectory(prefix='stage-',dir=CACHE) as directory:
        stage=Path(directory)
        with tarfile.open(archive) as bundle:bundle.extractall(stage,members=checked_members(bundle))
        count=license_metadata(licenses,stage/'licenses')
        (stage/'provenance.json').write_text(json.dumps(expected,indent=2)+'\n')
        if destination.exists():shutil.rmtree(destination)
        stage.rename(destination)
    print('已准备 Python '+lock['python_version']+'（'+target+'），保留 '+str(count)+' 份许可文本')
    return destination


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--target',choices=['aarch64-apple-darwin','x86_64-apple-darwin'])
    args=parser.parse_args();print(prepare(args.target))

if __name__=='__main__':main()
