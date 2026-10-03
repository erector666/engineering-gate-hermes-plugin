import sys, base64, hashlib, json, os, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"engineering-gate"))
from reviewer_service.key_cli import keygen
from engineering_gate_core.state_store import StateStore
from engineering_gate_core.mutation_authority import ReviewerKeyRegistry
from engineering_gate_core.signed_authorization import ReviewerPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def test_keygen_exclusive_private_file_mode_and_public_only_output(tmp_path):
    path=tmp_path/"signing.key"
    result=keygen(path)
    assert path.stat().st_mode & 0o777 == 0o600
    raw=path.read_bytes(); assert len(raw)==32
    public=Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    assert base64.b64decode(result["public_key_b64"])==public
    assert result["fingerprint_sha256"]==hashlib.sha256(public).hexdigest()
    try: keygen(path)
    except FileExistsError: pass
    else: raise AssertionError("keygen overwrote an existing key")

def test_operator_registry_register_list_and_revoke(tmp_path):
    db=tmp_path/"gate.sqlite"; store=StateStore(db); registry=ReviewerKeyRegistry(store)
    pub=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    record=ReviewerPublicKey("reviewer-key-1","engineering-gate-reviewer-v1","openai:gpt-6.1-sol",pub)
    registry.register_reviewer_key(record)
    saved=store.get_reviewer_key(record.key_id)
    assert saved.public_key==pub and saved.enabled and not saved.revoked
    registry.revoke_reviewer_key(record.key_id,reason="rotation")
    saved=store.get_reviewer_key(record.key_id)
    assert saved.revoked and not saved.enabled
    assert store.list_authorization_audit(key_id=record.key_id)

def test_api_key_file_requires_private_regular_file(tmp_path):
    from reviewer_service.service import _api_key
    path=tmp_path/"token"; path.write_text("dummy-local-test-key"); path.chmod(0o600)
    assert _api_key(path)=="dummy-local-test-key"
    path.chmod(0o644)
    try: _api_key(path)
    except ValueError: pass
    else: raise AssertionError("permissive API key accepted")

def test_key_cli_register_list_revoke_roundtrip(tmp_path):
    pub=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    pubfile=tmp_path/"reviewer.pub"; pubfile.write_bytes(pub)
    db=tmp_path/"registry.sqlite"
    env=os.environ.copy(); env["PYTHONPATH"]=str(ROOT/"engineering-gate")
    def cli(*args):
        return subprocess.run([sys.executable,"-m","reviewer_service.key_cli",*map(str,args)],env=env,text=True,capture_output=True,check=True).stdout.strip()
    cli("register","--database",db,"key-cli-1","engineering-gate-reviewer-v1","openai:gpt-6.1-sol",pubfile)
    listing=json.loads(cli("list","--database",db))
    assert listing==[{"key_id":"key-cli-1","reviewer_id":"engineering-gate-reviewer-v1","reviewer_provider":"openai:gpt-6.1-sol","fingerprint_sha256":hashlib.sha256(pub).hexdigest(),"enabled":True,"revoked":False}]
    cli("revoke","--database",db,"key-cli-1","--reason","operator rotation")
    listing=json.loads(cli("list","--database",db))
    assert listing[0]["revoked"] is True and listing[0]["enabled"] is False

def test_public_key_export_registers_existing_private_key_without_exposing_it(tmp_path):
    private=tmp_path/"reviewer.key"; public_file=tmp_path/"reviewer.pub"; db=tmp_path/"rotation.sqlite"
    env=os.environ.copy(); env["PYTHONPATH"]=str(ROOT/"engineering-gate")
    def cli(*args): return subprocess.run([sys.executable,"-m","reviewer_service.key_cli",*map(str,args)],env=env,text=True,capture_output=True,check=True).stdout.strip()
    generated=json.loads(cli("keygen",private))
    exported=cli("public-key",private,public_file)
    raw_private=private.read_bytes(); raw_public=public_file.read_bytes()
    assert len(raw_private)==32 and len(raw_public)==32 and raw_private not in exported.encode()
    assert raw_public==Ed25519PrivateKey.from_private_bytes(raw_private).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    cli("register","--database",db,"rotation-1","engineering-gate-reviewer-v1","openai:gpt-6.1-sol",public_file)
    saved=StateStore(db).get_reviewer_key("rotation-1")
    assert saved.public_key==raw_public and generated["fingerprint_sha256"]==hashlib.sha256(raw_public).hexdigest()
