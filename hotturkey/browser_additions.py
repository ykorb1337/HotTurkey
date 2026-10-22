"""Narrow append-only website operations for the extension popup."""
from urllib.parse import urlsplit,unquote

from .model import PolicyError


def site_target(url, scope):
    if not isinstance(url,str) or len(url)>8192 or any(ord(c)<32 for c in url):
        raise PolicyError('网页地址无效')
    try:
        parsed=urlsplit(url)
        if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError()
        host=parsed.hostname.rstrip('.').encode('idna').decode('ascii').lower()
        parsed.port  # Reject malformed ports even when adding only the domain.
        if not host or any(c in host for c in '* /\\?#'):raise ValueError()
    except (ValueError,UnicodeError):raise PolicyError('只能添加普通 HTTP 或 HTTPS 网页') from None
    if scope=='domain':return host
    if scope!='page':raise PolicyError('请选择整个域名或当前路径')
    path=unquote(parsed.path or '/')
    if '*' in path or any(ord(c)<32 for c in path):raise PolicyError('当前路径包含特殊字符，请改为添加整个域名')
    # Query strings and fragments can contain private tokens. Never save them.
    return parsed.scheme+'://'+host+path


def options(engine):
    return [{'id':b['id'],'name':b['name'],'enabled':b['enabled'],
             'locked':engine.locked(b),'mode':b['mode']}
            for b in engine.store.state['blocks'] if b['device']=='none']


def add_site(engine,data):
    target=site_target(data.get('url'),data.get('scope','domain'))
    block=engine.find(data.get('id'))
    if block['device']!='none':raise PolicyError('设备规则不能添加网站')
    added=target not in block['websites']
    result=engine.add_targets(block['id'],[target])
    from .model import target_matches
    # Make existing exceptions visible to the user without changing them.
    matches=target_matches(block,data['url'])
    return {'ok':True,'target':target,'added':added,'matches_current_page':matches,
            'block':{k:result[k] for k in ['id','name','enabled','locked','mode']}}
