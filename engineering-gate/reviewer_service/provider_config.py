"""Strict operator profiles and explicitly registered provider adapters."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib, ipaddress, json, math, os, stat
from pathlib import Path
from urllib.parse import urlsplit

MAX_PROFILE_BYTES = 16_384
MAX_LABEL = 48
MAX_MODEL = 96


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _text(value, maximum, *, colon=False):
    if type(value) is not str or not value or len(value) > maximum or value != value.strip(): raise ValueError("invalid identity")
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or (not colon and ":" in value): raise ValueError("invalid identity")
    return value


def provider_identity(provider: str, model: str) -> str:
    _text(provider, MAX_LABEL)
    _text(model, MAX_MODEL, colon=True)
    return f"{provider}:{model}"


def validate_endpoint(value: str) -> str:
    if type(value) is not str or len(value) > 2048: raise ValueError("invalid endpoint")
    try:
        u=urlsplit(value); host=u.hostname
        if u.username is not None or u.password is not None or u.query or u.fragment or not host: raise ValueError()
        if u.scheme=="https": return value
        if u.scheme!="http": raise ValueError()
        if host.lower()=="localhost": return value
        if not ipaddress.ip_address(host).is_loopback: raise ValueError()
        return value
    except Exception: raise ValueError("invalid endpoint") from None

@dataclass(frozen=True)
class ProviderProfile:
    provider: str; model: str; adapter: str; endpoint: str; api_key_file: str
    timeout_seconds: float; max_output_tokens: int; input_price_per_million_usd: float
    output_price_per_million_usd: float; daily_budget_usd: float; max_calls_per_day: int
    privacy: dict
    @property
    def provider_identity(self):
        return provider_identity(self.provider, self.model)


_ADAPTERS = {}
def register_adapter(name, factory):
    if type(name) is not str or not name or name in _ADAPTERS or not callable(factory): raise ValueError("invalid adapter registration")
    _ADAPTERS[name] = factory

def adapter_for(name, profile):
    try: factory = _ADAPTERS[name]
    except (KeyError, TypeError): raise ValueError("unknown provider adapter") from None
    return factory(profile)

class ResponsesAdapter:
    """Generic Responses-compatible transport; native protocols need registered adapters."""
    def __init__(self, profile): self.profile=profile
    def send(self, key, body):
        from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self,*a,**kw): return None
        opener=build_opener(ProxyHandler({}),NoRedirect())
        headers={"Content-Type":"application/json"}
        if key: headers["Authorization"]="Bearer "+key
        req=Request(self.profile.endpoint,data=json.dumps(body,ensure_ascii=False,separators=(",",":")).encode(),headers=headers,method="POST")
        with opener.open(req,timeout=self.profile.timeout_seconds) as response:
            raw=response.read(1_000_001)
            if len(raw)>1_000_000: raise ValueError()
            return json.loads(raw, object_pairs_hook=_no_duplicates)

register_adapter("responses", ResponsesAdapter)


def load_profile(path) -> ProviderProfile:
    fd=None
    try:
        flags=os.O_RDONLY | getattr(os,"O_CLOEXEC",0) | getattr(os,"O_NOFOLLOW",0)
        fd=os.open(os.fspath(path),flags)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o077: raise ValueError()
        if info.st_size > MAX_PROFILE_BYTES: raise ValueError()
        with os.fdopen(fd,"rb",closefd=False) as f: raw=f.read(MAX_PROFILE_BYTES+1)
        if len(raw)>MAX_PROFILE_BYTES: raise ValueError()
        d=json.loads(raw.decode("utf-8"),object_pairs_hook=_no_duplicates)
        required={"provider","model","adapter","endpoint","api_key_file","timeout_seconds","max_output_tokens","input_price_per_million_usd","output_price_per_million_usd","daily_budget_usd","max_calls_per_day","privacy"}
        if type(d) is not dict or set(d)!=required: raise ValueError()
        _text(d["provider"],MAX_LABEL); _text(d["model"],MAX_MODEL,colon=True)
        if type(d["adapter"]) is not str or not d["adapter"] or len(d["adapter"])>64: raise ValueError()
        if type(d["api_key_file"]) is not str: raise ValueError()
        endpoint=validate_endpoint(d["endpoint"])
        host=urlsplit(endpoint).hostname
        loopback=host.lower()=="localhost" or (_is_ip(host) and ipaddress.ip_address(host).is_loopback)
        if not d["api_key_file"] and not loopback: raise ValueError()
        if type(d["timeout_seconds"]) not in (int,float) or not math.isfinite(d["timeout_seconds"]) or not 1<=d["timeout_seconds"]<=300: raise ValueError()
        if type(d["max_output_tokens"]) is not int or not 1<=d["max_output_tokens"]<=2048: raise ValueError()
        for k in ("input_price_per_million_usd","output_price_per_million_usd","daily_budget_usd"):
            if type(d[k]) not in (int,float) or not math.isfinite(d[k]) or d[k]<0 or (k=="daily_budget_usd" and d[k]==0): raise ValueError()
        if type(d["max_calls_per_day"]) is not int or d["max_calls_per_day"]<1: raise ValueError()
        if type(d["privacy"]) is not dict or d["privacy"]!={"store":False,"tools":False}: raise ValueError()
        return ProviderProfile(**{**d,"endpoint":endpoint})
    except Exception: raise ValueError("invalid provider profile") from None
    finally:
        if fd is not None: os.close(fd)

def _is_ip(host):
    try: ipaddress.ip_address(host); return True
    except ValueError: return False
