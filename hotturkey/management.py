"""Shared validation for management operations; no privileged filesystem work."""
import copy

from .engine import password_hash
from .model import DEFAULT_SETTINGS,PolicyError,integer,validate_block,validate_text_encoding

STRICT_SETTINGS={'require_extension','block_unsupported','block_task_manager','block_settings',
                 'block_installer','extension_grace','block_inactive','block_embeds','allow_files','strict_usage','idle_seconds'}


def settings_update(engine,data):
    validate_text_encoding(data)
    current=engine.store.state['settings'];updated=copy.deepcopy(current)
    if 'password' in data:
        password=data['password']
        if not isinstance(password,str) or len(password)>5000:raise PolicyError('设置密码格式无效')
        updated['settings_password']=password_hash(password) if password else None
    locked=any(engine.locked(block) for block in engine.store.state['blocks'])
    for key,value in data.items():
        if key not in DEFAULT_SETTINGS or key in {'settings_password','device_recovery_hash'}:continue
        if locked and key in STRICT_SETTINGS and value!=current[key]:raise PolicyError('锁定期间不能修改拦截严格度')
        if isinstance(DEFAULT_SETTINGS[key],bool) and type(value) is not bool:raise PolicyError('设置值无效')
        updated[key]=value
    if updated['theme'] not in {'light','dark','system'}:raise PolicyError('主题无效')
    if updated['week_start'] not in {'monday','sunday'}:raise PolicyError('周起始日无效')
    for key,low,high in [('extension_grace',5,600),('idle_seconds',30,3600),('retention_days',1,3650),('text_scale',50,200)]:
        updated[key]=integer(updated[key],low,high,key)
    if not isinstance(updated['warning_minutes'],list):raise PolicyError('提醒时间无效')
    updated['warning_minutes']=[integer(value,1,1440,'提醒分钟') for value in updated['warning_minutes']]
    return updated


def import_blocks(engine,incoming,allow_autostart=False,confirm_device=False):
    if not isinstance(incoming,list) or len(incoming)>200:raise PolicyError('导入规则过多')
    if type(allow_autostart) is not bool or type(confirm_device) is not bool:raise PolicyError('导入选项无效')
    blocks=[];disabled=0
    for value in incoming:
        if not isinstance(value,dict):raise PolicyError('导入规则格式无效')
        block=validate_block({**value,'enabled':False})
        if block['autostart']['type']!='none':
            if not allow_autostart:block['autostart']={'type':'none'};disabled+=1
            elif block['device']!='none' and not confirm_device:raise PolicyError('保留设备自动启动需要确认设备动作')
            if allow_autostart and block['device']!='none' and not engine.store.state['settings']['device_recovery_hash']:raise PolicyError('请先设置设备限制的紧急安全词')
        blocks.append(block)
    names=[block['name'] for block in engine.store.state['blocks']]+[block['name'] for block in blocks]
    if len(set(names))!=len(names):raise PolicyError('导入名称重复，请先重命名')
    engine.store.state['blocks'].extend(blocks);engine.store.save()
    return {'count':len(blocks),'disabled_autostart':disabled}


def duplicate_block(engine,ident,name=None):
    block=copy.deepcopy(engine.find(ident))
    block.update(name=block['name']+' 副本' if name is None else name,enabled=False,autostart={'type':'none'})
    # Copying a device rule is inert; executing it still needs the usual explicit
    # confirmation when enabled. No original lock/runtime is changed.
    block['confirm_device']=True
    return engine.save_block(block)
