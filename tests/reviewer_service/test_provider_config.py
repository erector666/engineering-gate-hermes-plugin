import json, sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/"engineering-gate"),str(ROOT/"engineering-gate"/"engineering_gate_core")]
from reviewer_service.provider_config import load_profile, provider_identity, validate_endpoint, ResponsesAdapter

BASE={"provider":"example","model":"vendor-model-exact","adapter":"responses","endpoint":"https://api.example.test/v1/responses","api_key_file":"/fake/key","timeout_seconds":30,"max_output_tokens":512,"input_price_per_million_usd":1.25,"output_price_per_million_usd":4.5,"daily_budget_usd":3.0,"max_calls_per_day":4,"privacy":{"store":False,"tools":False}}

def test_loads_operator_profile_and_exact_provider_model_identity(tmp_path):
 p=tmp_path/"profile.json"; p.write_text(json.dumps(BASE)); p.chmod(0o600); c=load_profile(p)
 assert c.model==BASE["model"] and c.provider_identity=="example:vendor-model-exact"

def test_requires_all_profile_fields_and_rejects_invalid_prices(tmp_path):
 for key,value in (("provider",None),("input_price_per_million_usd",float("nan")),("max_calls_per_day",0)):
  d={**BASE,key:value}; p=tmp_path/"profile.json"; p.write_text(json.dumps(d))
  with pytest.raises(ValueError): load_profile(p)

def test_profile_rejects_zero_daily_budget(tmp_path):
 d={**BASE,"daily_budget_usd":0}; p=tmp_path/"profile.json"; p.write_text(json.dumps(d)); p.chmod(0o600)
 with pytest.raises(ValueError): load_profile(p)

def test_endpoint_validation_blocks_unsafe_url_forms():
 for url in ("http://example.test/api","http://localhost./api","https://u:p@example.test/api","https://example.test/api?x=1","https://example.test/api#frag"):
  with pytest.raises(ValueError): validate_endpoint(url)
 assert validate_endpoint("http://127.0.0.1:8080/v1/responses").startswith("http://127.0.0.1")
 assert validate_endpoint("https://api.example.test/v1/responses").startswith("https://")

def test_identity_uses_exact_provider_and_model():
 with pytest.raises(ValueError): provider_identity("Acme"," Model-X ")
 assert provider_identity("Acme","Model-X")=="Acme:Model-X"

def test_identity_is_unchanged_by_other_profile_settings(tmp_path):
 p=tmp_path/"profile.json"
 def make(**kw):
  d={**BASE,**kw}; p.write_text(json.dumps(d)); p.chmod(0o600); return load_profile(p)
 base=make()
 assert base.provider_identity=="example:vendor-model-exact"
 assert make(timeout_seconds=31, endpoint="https://other.example.test/review", daily_budget_usd=9.0, max_calls_per_day=99, input_price_per_million_usd=8.0).provider_identity==base.provider_identity
 for kw in ({"provider":"Acme:Other"},{"provider":"x"*1000},{"model":"bad\nmodel"},{"model":"x"*1000}):
  with pytest.raises(ValueError): make(**kw)

def test_strict_profile_file_and_duplicate_keys(tmp_path):
 p=tmp_path/"profile.json"; p.write_text(json.dumps(BASE)+" "+json.dumps(BASE)); p.chmod(0o600)
 # Duplicate keys are tested with valid JSON, not concatenated documents.
 p.write_text(json.dumps(BASE).replace('"provider": "example",','"provider": "example", "provider": "other",'))
 with pytest.raises(ValueError): load_profile(p)
 p.write_text(json.dumps(BASE)); p.chmod(0o644)
 with pytest.raises(ValueError): load_profile(p)
 link=tmp_path/"link"; link.symlink_to(p)
 with pytest.raises(ValueError): load_profile(link)

def test_loopback_may_omit_key_but_remote_may_not(tmp_path):
 p=tmp_path/"profile.json"; d={**BASE,"endpoint":"http://127.0.0.1:9999/v1/responses","api_key_file":""}; p.write_text(json.dumps(d)); p.chmod(0o600)
 assert load_profile(p).api_key_file==""
 d={**BASE,"endpoint":"http://localhost./v1/responses","api_key_file":""}; p.write_text(json.dumps(d))
 with pytest.raises(ValueError): load_profile(p)
 d={**BASE,"api_key_file":""}; p.write_text(json.dumps(d))
 with pytest.raises(ValueError): load_profile(p)

def test_adapter_registry_rejects_unknown():
 from reviewer_service.provider_config import adapter_for, ResponsesAdapter
 assert isinstance(adapter_for("responses",object()),ResponsesAdapter)
 with pytest.raises(ValueError): adapter_for("unknown",object())



def test_responses_adapter_rejects_duplicate_response_keys_and_parses_valid_json(monkeypatch):
    import urllib.request
    import reviewer_service.provider_config as module
    class Response:
        def __init__(self, payload): self.payload=payload
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return self.payload
    class Opener:
        def __init__(self, payload): self.payload=payload
        def open(self, req, timeout): return Response(self.payload)
    profile=type("Profile",(),{"endpoint":"https://api.example.test/v1/responses","timeout_seconds":30})()
    adapter=ResponsesAdapter(profile)
    for payload in (b'{"status":"ok","status":"failed"}', b'{"model":"one","model":"two"}'):
        monkeypatch.setattr(urllib.request,"build_opener",lambda *a, _payload=payload, **kw: Opener(_payload))
        with pytest.raises(ValueError): adapter.send("",{})
    payload=b'{"status":"ok","output":[]}'
    monkeypatch.setattr(urllib.request,"build_opener",lambda *a, **kw: Opener(payload))
    assert adapter.send("",{}) == {"status":"ok","output":[]}
