"""One policy engine shared by the desktop app, CLI and browser hosts."""
import copy
import datetime as dt
import getpass
import hashlib
import hmac
import secrets
import string
import time
from .model import PolicyError, validate_block, validate_break, integer, spans, target_matches, lines

def password_hash(password):
    if not isinstance(password,str) or not password or len(password)>5000:
        raise PolicyError("请输入密码（1–5000 个字符）")
    salt = secrets.token_hex(16)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200000).hex()

def password_ok(password, stored):
    try:
        salt, wanted = stored.split("$")
        actual = hashlib.pbkdf2_hmac("sha256", str(password).encode(), salt.encode(), 200000).hex()
        return hmac.compare_digest(actual,wanted)
    except (ValueError,AttributeError):
        return False

def challenge(length, mode="characters"):
    if mode=="words":
        words="focus calm build create learn read write rest walk breathe today time steady light forest river mountain paper pencil window garden kind clear begin finish thoughtful simple patient work space quiet purpose honest care wonder reflect choose progress effort balance".split()
        result=[]
        while len(" ".join(result))<length: result.append(secrets.choice(words))
        return " ".join(result)[:length]
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

class Engine:
    def __init__(self, store, wall=time.time, monotonic=time.monotonic, boot_id="test-boot", user=None):
        self.store, self.wall, self.monotonic = store, wall, monotonic
        self.boot_id, self.user = boot_id, user or getpass.getuser()
        self.anchor = max(wall(),store.state.get("last_time",0))
        self.mono_anchor = monotonic()
        self.heartbeats = {}
        self.sources = {}
        self.blocked_seen = {}
        self.start_time = self.now()
        self.last_prune = 0
        self.application_targets = None
        self.device_recovery_retry=0

    def now(self):
        return max(self.wall(), self.anchor + self.monotonic()-self.mono_anchor)

    def runtime(self, b):
        if hasattr(self.store,"runtime_for"):return self.store.runtime_for(b,self.now())
        return self.store.state["runtime"].setdefault(b["id"], {"started":self.now()})

    def find(self, ident):
        for b in self.store.state["blocks"]:
            if b["id"] == ident or b["name"] == ident:
                return b
        raise PolicyError("找不到该规则")

    def interval(self, b, now=None):
        now = self.now() if now is None else now
        if b["mode"] == "continuous":
            return (self.runtime(b).get("started",now), None, b["break"])
        local = dt.datetime.fromtimestamp(now)
        midnight = local.replace(hour=0,minute=0,second=0,microsecond=0)
        for back in (0,1):
            day = midnight - dt.timedelta(days=back)
            for row in b["schedule"]:
                if day.weekday() not in row["days"]:
                    continue
                start = (day + dt.timedelta(minutes=row["start"])).timestamp()
                end = (day + dt.timedelta(minutes=row["end"]+(1440 if row["end"]<row["start"] else 0))).timestamp()
                if start <= now < end:
                    return start,end,row.get("break",b["break"])
        return None

    def next_start(self,b):
        if b["mode"] != "scheduled":
            return None
        now = self.now()
        midnight = dt.datetime.fromtimestamp(now).replace(hour=0,minute=0,second=0,microsecond=0)
        starts = []
        for offset in range(8):
            day = midnight+dt.timedelta(days=offset)
            for row in b["schedule"]:
                if day.weekday() in row["days"]:
                    at = (day+dt.timedelta(minutes=row["start"])).timestamp()
                    if at > now:
                        starts.append(at)
        return min(starts) if starts else None

    def locked(self,b):
        return self.device_guard(b) or self.explicit_locked(b)

    def device_guard(self,b):
        return b.get('device','none')!='none' and b.get('enabled',False) and b.get('mode')=='scheduled' and self.interval(b) is not None

    def device_window(self,b):
        return (b['device']!='none' and b['enabled'] and self.interval(b) is not None
                and (b['mode']!='continuous' or self.runtime(b).get('device_until',0)>self.now()))

    def explicit_locked(self,b):
        lock, now = b.get("lock",{}), self.now()
        typ = lock.get("type","none")
        if typ == "none": return False
        if typ == "timer": return now < lock["until"]
        if typ == "restart": return lock.get("boot_id") == self.boot_id
        if typ == "range":
            sample = {"mode":"scheduled","schedule":lock["schedule"],"break":b["break"]}
            inside = self.interval(sample,now) is not None
            return not inside if lock.get("allow_inside") else inside
        if typ == "schedule":
            nxt = self.next_start(b)
            return bool(self.interval(b,now)) or bool(nxt and nxt-now <= lock.get("before_minutes",0)*60)
        return True

    def active(self,b):
        if b['device']!='none' and not self.store.state['settings']['device_recovery_hash']:return False
        if b['device']!='none' and self.runtime(b).get('device_emergency_until',0)>self.now():return False
        if b["device"]!="none" and b["mode"]=="continuous" and self.runtime(b).get("device_until",0)<=self.now():return False
        return b["enabled"] and (not b["users"] or self.user in b["users"]) and bool(self.interval(b))

    def start(self,b):
        rt=self.runtime(b)
        rt["started"]=self.now()
        rt.pop('pomodoro_started',None)
        if rt.get('device_emergency_until',0)<=self.now():rt.pop('device_emergency_until',None)
        if b["device"]!="none" and b["mode"]=="continuous":
            rt["device_until"]=self.now()+b.get("device_minutes",15)*60
            b["lock"]={"type":"timer","until":rt["device_until"]}
        if hasattr(self.store,"block_started"):self.store.block_started(b,self.now())

    def period_start(self,b,br,now):
        local = dt.datetime.fromtimestamp(now)
        pivot = local.replace(hour=0,minute=0,second=0,microsecond=0)+dt.timedelta(minutes=br["refill_minute"])
        if pivot.timestamp()>now: pivot-=dt.timedelta(days=1)
        period = br["period"]
        if period == "rolling": return now-br["window_minutes"]*60
        if period == "schedule": return self.interval(b,now)[0]
        if period == "week": pivot-=dt.timedelta(days=pivot.weekday())
        if period == "month": pivot=pivot.replace(day=1)
        return pivot.timestamp()

    def break_state(self,b):
        now, rt = self.now(), self.runtime(b)
        interval = self.interval(b,now)
        br = interval[2] if interval else b["break"]
        typ = br["type"]
        if rt.get("break_until",0)>now:
            return {"allowed":True,"type":typ,"remaining":rt["break_until"]-now,"label":"休息中"}
        if typ == "pomodoro" and interval:
            start = interval[0]
            if b["mode"] == "continuous":
                midnight=dt.datetime.fromtimestamp(now).replace(hour=0,minute=0,second=0,microsecond=0).timestamp()
                start=max(start,midnight,rt.get('pomodoro_started',start))
            work, rest=br["work_minutes"]*60,br["break_minutes"]*60
            phase=(now-start)%(work+rest)
            allowed=phase>=work
            return {"allowed":allowed,"type":typ,"remaining":work+rest-phase if allowed else work-phase,"label":"番茄休息" if allowed else "专注中"}
        if typ in {"allowance","sessions","reward"} and interval:
            since=self.period_start(b,br,now)
            if typ=="allowance":
                remaining=max(0,br["allowance_minutes"]*60-self.store.used(b["id"],since))
            else:
                key=str(since) if br["period"]!="rolling" else "rolling"
                if rt.get("period")!=key:
                    rt.update(period=key,sessions_used=0,reward_credit=0,focus_seconds=0,last_activity=0)
                if typ=="sessions":
                    ongoing=now-rt.get("last_activity",0)<120
                    remaining=max(0,br["sessions"]-rt.get("sessions_used",0))
                    return {"allowed":ongoing or remaining>0,"type":typ,"remaining":remaining,"label":"可用会话"}
                remaining=max(0,rt.get("reward_credit",0))
            return {"allowed":remaining>0,"type":typ,"remaining":remaining,"label":"可用额度" if typ=="allowance" else "已赚取休息"}
        return {"allowed":False,"type":typ,"remaining":0,"label":"无休息" if typ=="none" else "可申请休息"}

    def status(self,b):
        s=copy.deepcopy(b)
        s["lock"].pop("hash",None)
        s["locked"]=self.locked(b)
        if self.device_guard(b) and not self.explicit_locked(b):
            s['lock']={'type':'schedule','before_minutes':0,'automatic_device':True}
        s["active"]=self.active(b)
        s["break_status"]=self.break_state(b)
        s["blocking"]=s["active"] and not s["break_status"]["allowed"]
        s["next_start"]=self.next_start(b)
        if b['device']!='none':
            s['device_recovery_required']=not bool(self.store.state['settings']['device_recovery_hash'])
            s['device_emergency_until']=self.runtime(b).get('device_emergency_until',0)
        if b["device"]!="none" and b["mode"]=="continuous":s["device_remaining"]=max(0,self.runtime(b).get("device_until",0)-self.now())
        if b['device']!='none' and b['mode']=='scheduled':
            window=self.interval(b)
            if window:s.update(device_until=window[1],device_remaining=max(0,window[1]-self.now()))
        return s

    def snapshot(self):
        with self.store.lock:
            settings=copy.deepcopy(self.store.state["settings"])
            settings["settings_password"]=bool(settings["settings_password"])
            settings['device_recovery_hash']=bool(settings['device_recovery_hash'])
            return {"blocks":[self.status(b) for b in self.store.state["blocks"]],"settings":settings,"now":self.now(),"user":self.user,"extensions":copy.deepcopy(self.heartbeats)}

    def save_block(self,value,ident=None):
        if isinstance(value,dict) and 'confirm_device' in value and type(value['confirm_device']) is not bool:raise PolicyError('设备动作确认无效')
        with self.store.lock:
            previous=self.find(ident) if ident else None
            if previous and self.locked(previous): raise PolicyError("规则已锁定，可新增屏蔽网站和应用；其他修改须先解锁")
            b=validate_block(value,previous)
            if b['device']!='none' and (b['enabled'] or b['autostart']['type']!='none') and not self.store.state['settings']['device_recovery_hash']:
                raise PolicyError('请先设置设备限制的紧急安全词')
            if b["autostart"].get("type")!="none" and b["device"]!="none" and not value.get("confirm_device"):
                if not previous or previous.get("autostart")!=b["autostart"]:
                    raise PolicyError("设备自动启动需要确认设备动作")
            if any(x["name"]==b["name"] and x is not previous for x in self.store.state["blocks"]): raise PolicyError("规则名称已存在")
            if b["device"]!="none" and (not previous or previous["device"]!=b["device"] or (b["enabled"] and not previous["enabled"])) and not value.get("confirm_device"):
                raise PolicyError("设备规则会锁屏、注销或关机，请确认设备动作")
            b.pop("confirm_device",None)
            if previous:
                index=self.store.state["blocks"].index(previous)
                self.store.state["blocks"][index]=b
            else: self.store.state["blocks"].append(b)
            if b["enabled"] and (not previous or not previous["enabled"]):self.start(b)
            self.store.save()
            return self.status(b)

    def add_targets(self,ident,websites=None,applications=None):
        """Merge additions against the latest policy without touching its lock or runtime."""
        with self.store.lock:
            b=self.find(ident)
            additions={"websites":lines([] if websites is None else websites),
                       "applications":lines([] if applications is None else applications)}
            merged={key:lines(list(dict.fromkeys(b[key]+values))) for key,values in additions.items()}
            # Validate both lists before mutating either one, including the combined limit.
            b.update(merged)
            self.store.save()
            return self.status(b)

    def delete(self,ident):
        with self.store.lock:
            b=self.find(ident)
            if self.locked(b): raise PolicyError("无法删除锁定中的规则")
            self.store.state["blocks"].remove(b)
            self.store.state["runtime"].pop(b["id"],None)
            if hasattr(self.store,"block_deleted"):self.store.block_deleted(b["id"])
            self.store.save()

    def toggle(self,ident,enabled=None,confirm_device=False):
        if enabled is not None and type(enabled) is not bool:raise PolicyError('启用状态无效')
        if type(confirm_device) is not bool:raise PolicyError('设备动作确认无效')
        with self.store.lock:
            b=self.find(ident)
            if self.locked(b): raise PolicyError("规则已锁定")
            desired=not b["enabled"] if enabled is None else bool(enabled)
            if desired and b["device"]!="none" and not confirm_device: raise PolicyError("请确认设备动作")
            if desired and b['device']!='none' and not self.store.state['settings']['device_recovery_hash']:raise PolicyError('请先设置设备限制的紧急安全词')
            if desired and not b["enabled"]:self.start(b)
            b["enabled"]=desired
            self.store.save()
            return self.status(b)

    def reset_pomodoro(self,ident):
        with self.store.lock:
            b=self.find(ident)
            if b['mode']!='continuous' or b['break']['type']!='pomodoro':
                raise PolicyError('只能重置持续生效规则的番茄钟')
            if not self.active(b):raise PolicyError('该规则目前未生效')
            # A new work period can only postpone the next break. Keep the rule's
            # start time, device deadline, lock and all other break accounting.
            now=self.now()
            rt=self.runtime(b)
            rt['pomodoro_started']=now
            rt.pop('break_until',None)
            if hasattr(self.store,'pomodoro_reset'):self.store.pomodoro_reset(b,now)
            self.store.save()
            return self.status(b)

    def set_lock(self,ident,data):
        with self.store.lock:
            b=self.find(ident)
            typ=data.get("type","none")
            if typ not in {"none","timer","range","text","password","delay","schedule","restart"}: raise PolicyError("锁定类型无效")
            old=b["lock"]
            if self.locked(b):
                if old["type"]=="timer" and typ=="timer" and data.get("until",0)>=old["until"]:
                    old["until"]=float(data["until"])
                    if b["device"]!="none" and b["mode"]=="continuous":self.runtime(b)["device_until"]=old["until"]
                    if b["device"]!="none" and b["mode"]=="continuous" and hasattr(self.store,"device_deadline_changed"):self.store.device_deadline_changed(b,old["until"])
                    self.store.save()
                    return self.status(b)
                if old['type']=='text' and typ=='text':
                    length=integer(data.get('length'),1,5000,'文本长度')
                    extra=length-len(old['text'])
                    if extra<=0:raise PolicyError('新文本长度须大于当前长度')
                    mode=old.get('text_mode','characters')
                    suffix=(' '+challenge(extra-1,mode)) if mode=='words' and extra>1 and not old['text'].endswith(' ') else challenge(extra,mode)
                    old['text']+=suffix
                    self.store.save()
                    return self.status(b)
                raise PolicyError("须先解锁；定时锁与验证文本只能延长")
            lock={"type":typ}
            if typ=="timer":
                until=data.get("until",0)
                if not isinstance(until,(int,float)) or not self.now()<until<=self.now()+10*365*86400: raise PolicyError("锁定结束时间无效")
                lock["until"]=until
            if typ=="password": lock["hash"]=password_hash(data.get("password"))
            if typ=="text":
                if data.get("text_mode","characters") not in {"characters","words"}: raise PolicyError("文本类型无效")
                lock["text"]=str(data.get("custom_text") or challenge(integer(data.get("length",50),1,5000,"文本长度"),data.get("text_mode","characters")))[:5000]
                lock['text_mode']=data.get('text_mode','characters')
            if typ=="delay": lock["minutes"]=integer(data.get("minutes",1),1,57600,"等待分钟")
            if typ=="restart": lock["boot_id"]=self.boot_id
            if typ=="range":
                lock["schedule"]=spans(data.get("schedule",[]))
                if not lock["schedule"]: raise PolicyError("请添加锁定时段")
                lock["allow_inside"]=bool(data.get("allow_inside",False))
            if typ=="schedule":
                if b["mode"]!="scheduled": raise PolicyError("请先配置每周日程")
                lock["before_minutes"]=integer(data.get("before_minutes",0),0,1440,"提前锁定分钟")
            b["lock"]=lock
            self.store.save()
            return self.status(b)

    def unlock(self,ident,data):
        with self.store.lock:
            b=self.find(ident)
            if self.device_guard(b):raise PolicyError('强制休息时段尚未结束，不能解除设备限制')
            lock=b["lock"]
            if self.locked(b):
                typ=lock["type"]
                if typ=="password":
                    if self.now()<lock.get("retry_at",0): raise PolicyError("请稍后重试密码")
                    if not password_ok(data.get("answer",""),lock["hash"]):
                        lock["retry_at"]=self.now()+2
                        self.store.save()
                        raise PolicyError("密码不正确")
                elif typ=="text":
                    if data.get("answer")!=lock["text"]: raise PolicyError("文本不一致，请完整输入")
                elif typ=="delay":
                    if not lock.get("ready_at"):
                        lock["ready_at"]=self.now()+lock["minutes"]*60
                        self.store.save()
                        return {"ready_at":lock["ready_at"]}
                    if self.now()<lock["ready_at"]: raise PolicyError("等待倒计时尚未结束")
                else: raise PolicyError("锁定条件尚未满足")
            b["lock"]={"type":"none"}
            self.store.save()
            return self.status(b)

    def configure_device_recovery(self,word,previous_word=None):
        with self.store.lock:
            if not isinstance(word,str) or not 6<=len(word)<=256:raise PolicyError('安全词需为 6–256 个字符')
            if word!=word.strip():raise PolicyError('安全词首尾不能包含空白')
            stored=self.store.state['settings']['device_recovery_hash']
            if stored and any(b['device']!='none' and self.locked(b) for b in self.store.state['blocks']):
                if not isinstance(previous_word,str) or not password_ok(previous_word,stored):raise PolicyError('设备限制期间更改安全词需要验证原安全词')
            self.store.state['settings']['device_recovery_hash']=password_hash(word);self.store.save()
            return {'ok':True}

    def recover_device(self,word,stop_plan=False):
        with self.store.lock:
            if type(stop_plan) is not bool:raise PolicyError('紧急停用选项无效')
            if self.monotonic()<self.device_recovery_retry:raise PolicyError('请稍后重试安全词')
            if not isinstance(word,str) or len(word)>256:raise PolicyError('安全词格式无效')
            stored=self.store.state['settings']['device_recovery_hash']
            if not stored or not password_ok(word,stored):
                self.device_recovery_retry=self.monotonic()+3
                raise PolicyError('安全词不正确')
            affected=[];until=self.now()
            for block in self.store.state['blocks']:
                if block['device']=='none' or not (self.device_window(block) if stop_plan else self.active(block)):continue
                end=self.runtime(block).get('device_until',0) if block['mode']=='continuous' else self.interval(block)[1]
                until=max(until,end);affected.append(block)
            if not affected:raise PolicyError('当前没有生效的设备限制')
            for block in affected:
                self.runtime(block)['device_emergency_until']=until
                if stop_plan:block.update(enabled=False,autostart={'type':'none'},lock={'type':'none'})
            self.store.save();return {'ok':True,'until':until,'count':len(affected),'stopped':stop_plan}

    def request_break(self,ident,data):
        with self.store.lock:
            b=self.find(ident)
            if not self.active(b): raise PolicyError("该规则目前未生效")
            br=self.interval(b)[2]
            rt=self.runtime(b)
            if rt.get("break_until",0)>self.now(): raise PolicyError("已在休息中")
            if br["type"]=="text":
                text=rt.setdefault("break_text",br["custom_text"] or challenge(br["text_length"],br["text_mode"]))
                if "answer" not in data:
                    self.store.save()
                    return {"challenge":text}
                if data["answer"]!=text: raise PolicyError("休息验证文本不一致")
                rt.pop("break_text",None)
            elif br["type"]=="delay":
                if not rt.get("break_ready"):
                    rt["break_ready"]=self.now()+br["delay_minutes"]*60
                    self.store.save()
                    return {"ready_at":rt["break_ready"]}
                if self.now()<rt["break_ready"]: raise PolicyError("休息倒计时尚未结束")
                rt.pop("break_ready",None)
            else: raise PolicyError("该规则未配置文本或等待休息")
            rt["break_until"]=self.now()+br["break_minutes"]*60
            self.store.save()
            return self.status(b)

    def evaluate(self,url,channels=(),active=True,embedded=False,exemptions=()):
        with self.store.lock:
            import re
            from urllib.parse import urlsplit
            settings=self.store.state["settings"]
            if url.startswith("file:") and settings["allow_files"]: return {"blocked":False,"blocks":[]}
            if (not active and not settings["block_inactive"]) or (embedded and not settings["block_embeds"]): return {"blocked":False,"blocks":[]}
            found=[]
            parsed=urlsplit(url)
            needs_channel=(parsed.hostname or "").endswith("youtube.com") and parsed.path.startswith(("/watch","/shorts/")) and not channels
            pending_channel=False
            for b in self.store.state["blocks"]:
                if b['id'] in exemptions:continue
                if needs_channel and self.active(b) and any(re.search(r"youtube\.com/(?:@|channel/|c/|user/)",p) for p in b["websites"]+b["exceptions"]):
                    pending_channel=True
                if self.active(b) and target_matches(b,url,channels) and not self.break_state(b)["allowed"]:
                    found.append({"id":b["id"],"name":b["name"],"break":self.break_state(b),"lock":self.status(b)["lock"],"exceptions":b["exceptions"]})
            return {"blocked":bool(found),"blocks":found,"pending_channel":pending_channel}

    def usage(self,data,source,exemptions=(),policy_ids=None,seconds_limit=None):
        with self.store.lock:
            now=self.now()
            # Time is measured by the daemon, never trusted from the browser.
            previous=self.sources.get(source,now)
            self.sources[source]=now
            seconds=max(0,min(10,now-previous))
            if seconds_limit is not None:seconds=min(seconds,max(0,seconds_limit))
            settings=self.store.state["settings"]
            idle=max(0,float(data.get("idle",0)))
            if idle>settings["idle_seconds"] and not data.get("playing"): return
            if not data.get("active",True) and not settings["strict_usage"]: return
            target=str(data.get("url") or data.get("application") or "")[:2048]
            if not target: return
            kind="website" if data.get("url") else "application"
            if kind=="website":
                from urllib.parse import urlsplit
                target=urlsplit(target).hostname or target
            affected=[]
            for b in self.store.state["blocks"]:
                if policy_ids is not None and b['id'] not in policy_ids:continue
                if not self.active(b): continue
                hit=target_matches(b,data["url"],data.get("channels",())) if kind=="website" else self.app_matches(b,data)
                rt=self.runtime(b)
                br=self.interval(b)[2]
                bs=self.break_state(b)
                if hit:
                    if kind=='website' and b['id'] in exemptions:
                        affected.append(b['id'])
                        continue
                    if not bs["allowed"]: continue
                    # Multiple tabs/processes count once toward the same allowance.
                    charged=max(0,min(seconds,now-rt.get("last_charge",now-seconds)))
                    rt["last_charge"]=now
                    if br["type"]=="allowance": self.store.charge(now,b["id"],charged)
                    if br["type"]=="sessions":
                        if now-rt.get("last_activity",0)>=120: rt["sessions_used"]=rt.get("sessions_used",0)+1
                        rt["last_activity"]=now
                    if br["type"]=="reward": rt["reward_credit"]=max(0,rt.get("reward_credit",0)-charged)
                    affected.append(b["id"])
                elif br["type"]=="reward":
                    charged=max(0,min(seconds,now-rt.get("last_focus",now-seconds)))
                    rt["last_focus"]=now
                    rt["focus_seconds"]=rt.get("focus_seconds",0)+charged
                    earned=int(rt["focus_seconds"]//(br["work_minutes"]*60))
                    if earned:
                        rt["reward_credit"]=rt.get("reward_credit",0)+earned*br["break_minutes"]*60
                        rt["focus_seconds"]%=br["work_minutes"]*60
            if settings["statistics"] and (not data.get("incognito") or settings["incognito_statistics"]):
                self.store.event(now,self.user,kind,target,affected[0] if affected else "",seconds,block_ids=affected)
            self.store.save()

    def app_matches(self,b,data):
        import fnmatch
        path=data.get("path","")
        bundle=data.get("bundle","")
        name=data.get("application","")
        rules=(target for rule in b["applications"] for target in (self.application_targets(rule) if self.application_targets else [rule]))
        for rule in rules:
            if rule.startswith("bundle:") and bundle==rule[7:]: return True
            if rule.startswith("folder:") and path.startswith(rule[7:].rstrip("/")+"/"): return True
            if rule.startswith("binary:") and data.get("executable",path)==rule[7:]: return True
            if path==rule or path.startswith(rule.rstrip("/")+"/Contents/"): return True
            if not rule.startswith("/") and fnmatch.fnmatchcase(name.lower(),rule.lower()): return True
        return False

    def record_block(self,target,block_ids,kind="website",incognito=False):
        now=self.now()
        recorded=[]
        for ident in block_ids:
            key=(target,ident,kind)
            if now-self.blocked_seen.get(key,0)<5: continue
            self.blocked_seen[key]=now
            recorded.append(ident)
        if recorded and self.store.state["settings"]["statistics"] and (not incognito or self.store.state["settings"]["incognito_statistics"]):
            self.store.event(now,self.user,kind,target,recorded[0],0,True,block_ids=recorded)

    def tick(self,signin=False):
        with self.store.lock:
            now=self.now()
            local=dt.datetime.fromtimestamp(now)
            date=local.date().isoformat()
            for b in self.store.state["blocks"]:
                auto=b.get("autostart",{})
                rt=self.runtime(b)
                auto_rt=self.store.autostart_runtime(b) if hasattr(self.store,"autostart_runtime") else rt
                typ=auto.get("type")
                if b["enabled"] and b["device"]!="none" and b["mode"]=="continuous" and rt.get("device_until",0)<=now:
                    b["enabled"]=False
                due=(typ=="once" and now>=auto.get("at",1e20) and not auto_rt.get("once_fired"))
                due=due or (typ=="daily" and local.weekday() in auto.get("days",[]) and local.hour*60+local.minute>=auto.get("minute",1440) and auto_rt.get("daily_fired")!=date)
                due=due or (typ=="signin" and signin and (not b["users"] or self.user in b["users"]))
                due=due or (typ=="schedule" and self.interval(b) and auto_rt.get("schedule_fired")!=self.interval(b)[0])
                if due and b['device']!='none' and not self.store.state['settings']['device_recovery_hash']:continue
                # Waking during an emergency release must not extend its original
                # device deadline and resume restriction as soon as release ends.
                if due and b['device']!='none' and rt.get('device_emergency_until',0)>now:continue
                if due:
                    b["enabled"]=True
                    self.start(b)
                    auto_rt.update(once_fired=True,daily_fired=date)
                    if self.interval(b): auto_rt["schedule_fired"]=self.interval(b)[0]
            self.store.state["last_time"]=now
            self.store.save()
            if now-self.last_prune>3600:
                self.store.prune(now)
                self.last_prune=now
