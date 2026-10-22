"""Validated, serializable policy definitions. No OS side effects."""
import copy
import math
import re
import uuid
from urllib.parse import urlsplit, unquote

LOCKS = {"none", "timer", "range", "text", "password", "delay", "schedule", "restart"}
BREAKS = {"none", "pomodoro", "allowance", "reward", "text", "delay", "sessions"}
PERIODS = {"day", "week", "month", "rolling", "schedule"}
CATEGORIES = {
    "社交网络": ["facebook.com", "instagram.com", "x.com", "twitter.com", "reddit.com", "tiktok.com", "weibo.com", "xiaohongshu.com"],
    "视频与直播": ["youtube.com", "twitch.tv", "netflix.com", "bilibili.com", "douyin.com", "huya.com"],
    "游戏": ["store.steampowered.com", "epicgames.com", "roblox.com", "chess.com"],
    "新闻": ["cnn.com", "bbc.com", "nytimes.com", "news.google.com"],
    "购物": ["amazon.com", "ebay.com", "taobao.com", "jd.com", "temu.com"],
}
DEFAULT_SETTINGS = {
    "theme": "light", "statistics": True, "incognito_statistics": True,
    "block_inactive": False, "block_embeds": True, "allow_files": True,
    "strict_usage": False, "idle_seconds": 180, "extension_grace": 60,
    "require_extension": False, "block_unsupported": False,
    "block_task_manager": False, "block_settings": False, "block_installer": False,
    "notifications": True, "warning_minutes": [2, 5], "retention_days": 90,
    "week_start": "monday", "clock_24": True,
    "settings_password": None, "protect_overview": False,
    "open_at_login": False, "start_in_tray": False,
}

class PolicyError(ValueError):
    pass

def integer(value, low, high, label):
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or int(value) != value or not low <= value <= high:
        raise PolicyError(f"{label}必须为 {low}–{high} 的整数")
    return int(value)

def lines(value):
    if isinstance(value, str):
        value = value.splitlines()
    if not isinstance(value, list) or len(value) > 10000:
        raise PolicyError("规则须为文本列表，最多 10000 条")
    result = []
    for item in value:
        if not isinstance(item, str) or len(item) > 2048 or any(ord(c) < 32 for c in item):
            raise PolicyError("规则格式无效")
        item = item.strip()
        if item and item not in result:
            result.append(item)
    return result

def spans(value):
    if not isinstance(value, list) or len(value) > 200:
        raise PolicyError("日程格式无效")
    result = []
    occupied = set()
    for row in value:
        if not isinstance(row, dict):
            raise PolicyError("日程格式无效")
        days = sorted(set(integer(x, 0, 6, "星期") for x in row.get("days", [])))
        start = integer(row.get("start"), 0, 1439, "开始分钟")
        end = integer(row.get("end"), 1, 1440, "结束分钟")
        if not days or start == end:
            raise PolicyError("请至少选择一天，且开始与结束时间须不同")
        for day in days:
            duration = (end - start) % 1440 or 1440
            for offset in range(duration):
                cell = (day * 1440 + start + offset) % 10080
                if cell in occupied:
                    raise PolicyError("同一规则内的日程不能重叠")
                occupied.add(cell)
        item = {"id": str(row.get("id") or uuid.uuid4()), "days": days, "start": start, "end": end}
        if row.get("break"):
            item["break"] = validate_break(row["break"])
        result.append(item)
    return result

def validate_break(value):
    v = copy.deepcopy(value or {})
    if not isinstance(v, dict) or v.get("type", "none") not in BREAKS:
        raise PolicyError("休息类型无效")
    v["type"] = v.get("type", "none")
    for k, default, high in [("work_minutes",25,57600),("break_minutes",5,1440),("allowance_minutes",30,57600),("window_minutes",60,57600),("delay_minutes",1,57600),("sessions",3,10000),("text_length",30,5000),("refill_minute",0,1439)]:
        v[k] = integer(v.get(k, default), 0 if k == "refill_minute" else 1, high, k)
    v["period"] = v.get("period", "day")
    if v["period"] not in PERIODS:
        raise PolicyError("额度补充周期无效")
    if v["period"]=="rolling" and v["type"] in {"reward","sessions"}:
        raise PolicyError("滚动周期只适用于使用额度")
    v["custom_text"] = str(v.get("custom_text", ""))[:5000]
    v["text_mode"] = v.get("text_mode", "characters")
    if v["text_mode"] not in {"characters","words"}:
        raise PolicyError("文本类型无效")
    return v

def validate_block(value, previous=None):
    if not isinstance(value, dict):
        raise PolicyError("规则格式无效")
    b = copy.deepcopy(value)
    b["id"] = previous["id"] if previous else str(uuid.uuid4())
    b["name"] = str(b.get("name", "")).strip()[:100]
    if not b["name"]:
        raise PolicyError("请输入规则名称")
    for key in ("websites", "exceptions", "applications"):
        b[key] = lines(b.get(key, []))
    b["users"] = lines(b.get("users", []))
    b["enabled"] = bool(b.get("enabled", False))
    b["color"] = b.get("color", "#c3623e")
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", b["color"]):
        raise PolicyError("颜色无效")
    b["mode"] = b.get("mode", "continuous")
    if b["mode"] not in {"continuous", "scheduled"}:
        raise PolicyError("日程模式无效")
    b["schedule"] = spans(b.get("schedule", []))
    if b["mode"] == "scheduled" and not b["schedule"]:
        raise PolicyError("请先添加日程")
    b["break"] = validate_break(b.get("break"))
    # Locks and runtime can only be changed by dedicated authenticated operations.
    b["lock"] = copy.deepcopy(previous.get("lock", {"type":"none"}) if previous else {"type":"none"})
    b["autostart"] = copy.deepcopy(b.get("autostart", {"type":"none"}))
    if not isinstance(b["autostart"],dict):raise PolicyError("自动启动格式无效")
    if b["autostart"].get("type") not in {"none","once","daily","signin","schedule"}:
        raise PolicyError("自动启动类型无效")
    auto = b["autostart"]
    if auto["type"] == "once":
        if not isinstance(auto.get("at"), (int,float)) or not math.isfinite(auto["at"]) or auto["at"] <= 0:
            raise PolicyError("自动启动时间无效")
    if auto["type"] == "daily":
        auto["minute"] = integer(auto.get("minute"), 0, 1439, "自动启动分钟")
        auto["days"] = [integer(d,0,6,"星期") for d in auto.get("days",range(7))]
    b["device"] = b.get("device", "none")
    if b["device"] not in {"none","lock","logout","shutdown"}:
        raise PolicyError("设备动作无效")
    b["device_minutes"]=integer(b.get("device_minutes",15),1,1440,"设备拦截分钟")
    return b

def glob(pattern, value):
    return re.fullmatch(".*".join(re.escape(part) for part in pattern.split("*")), value, re.DOTALL) is not None

def browser_page(url):
    """Return only browser-owned pages; extension and website URLs are excluded."""
    if not isinstance(url,str):return None
    try:
        parsed=urlsplit(url)
        scheme=parsed.scheme.lower()
        if scheme=='about':
            page,_,path=parsed.path.partition('/')
        elif scheme in {'chrome','edge','brave','vivaldi','opera'}:
            page,path=parsed.hostname or '',parsed.path.lstrip('/')
        else:return None
        if not page:return None
        suffix=('/'+path if path else '')+('?' + parsed.query if parsed.query else '')+('#'+parsed.fragment if parsed.fragment else '')
        return scheme,page.lower(),unquote(suffix).lower()
    except (ValueError,UnicodeError):return None

def browser_page_matches(pattern,url):
    actual=browser_page(url)
    wanted=browser_page(pattern)
    if not actual or not wanted:return False
    scheme,page,suffix=actual
    wanted_scheme,wanted_page,expected=wanted
    if wanted_scheme!=scheme and not (wanted_scheme=='chrome' and scheme in {'brave','vivaldi','opera'}):return False
    # These pages must be named explicitly so a broad wildcard preserves access.
    if page in {'newtab','newtab-page','extensions','addons','welcome','home'} and wanted_page!=page:return False
    if not glob(wanted_page,page):return False
    if not expected:return True
    return glob(expected,suffix) if '*' in expected else suffix.startswith(expected)

def matches(pattern, url):
    """Domain boundaries, path prefixes, explicit schemes, URL globs and IDNs."""
    pattern = pattern.strip().lower()
    if not pattern or not isinstance(url, str):
        return False
    if re.match(r'^(?:chrome|edge|brave|vivaldi|opera|about):',url,re.I):return browser_page_matches(pattern,url)
    try:
        u = urlsplit(url if "://" in url else "https://" + url)
        host = (u.hostname or "").lower().encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        return False
    if pattern == "*.*":
        return u.scheme in {"http","https","ftp"}
    if pattern in {"*", "http*://*"}:
        return True
    explicit = "://" in pattern
    if explicit:
        scheme, pattern = pattern.split("://", 1)
        if not glob(scheme, u.scheme):
            return False
    path = unquote(u.path or "/") + ("?" + unquote(u.query) if u.query else "") + ("#" + unquote(u.fragment) if u.fragment else "")
    if pattern.startswith("*") and not pattern.startswith("*.") and ("/" not in pattern or pattern.startswith("*/")):
        return glob(pattern, host + path.lower()) or glob(pattern, host)
    domain, sep, wanted_path = pattern.partition("/")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    if "*" in domain:
        domain_ok = glob(domain, host)
    else:
        domain_ok = host == domain or host.endswith("." + domain)
    if not domain_ok:
        return False
    if not sep:
        return True
    expected = "/" + wanted_path
    if "*" in expected:
        return glob(expected, path.lower())
    return path.lower().startswith(expected)

def target_matches(block, url, channels=()):
    urls = [url] + list(channels)
    return any(matches(p,u) for p in block["websites"] for u in urls) and not any(matches(p,u) for p in block["exceptions"] for u in urls)
