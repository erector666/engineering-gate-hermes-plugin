"""Operator-only reviewer signing key bootstrap and registry administration."""
from __future__ import annotations
import argparse, hashlib, json, os, stat, sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from engineering_gate_core.models import *  # noqa: F401,F403
from engineering_gate_core.state_store import StateStore
from engineering_gate_core.mutation_authority import ReviewerKeyRegistry
from engineering_gate_core.signed_authorization import ReviewerPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def keygen(path):
    target=Path(path)
    raw=__import__('secrets').token_bytes(32)
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
    except BaseException:
        try: target.unlink()
        except OSError: pass
        raise
    pub=Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    return {"public_key_b64":__import__('base64').b64encode(pub).decode(),"fingerprint_sha256":hashlib.sha256(pub).hexdigest()}

def export_public_key(private_path, public_path):
    from reviewer_service.service import load_private_key
    raw=load_private_key(private_path)
    public=Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    target=Path(public_path)
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        with os.fdopen(fd,"wb") as f: f.write(public); f.flush(); os.fsync(f.fileno())
    except BaseException:
        try: target.unlink()
        except OSError: pass
        raise
    return {"fingerprint_sha256":hashlib.sha256(public).hexdigest(),"public_key_file":str(target)}

def main(argv=None):
    p=argparse.ArgumentParser(prog="reviewer-key"); sub=p.add_subparsers(dest="cmd",required=True)
    g=sub.add_parser("keygen"); g.add_argument("private_key_file")
    x=sub.add_parser("public-key"); x.add_argument("private_key_file"); x.add_argument("public_key_file")
    for name in ("register","list","revoke"):
        q=sub.add_parser(name); q.add_argument("--database",required=True)
        if name=="register": q.add_argument("key_id"); q.add_argument("reviewer_id"); q.add_argument("reviewer_provider"); q.add_argument("public_key_file")
        if name=="revoke": q.add_argument("key_id"); q.add_argument("--reason",required=True)
    a=p.parse_args(argv)
    if a.cmd=="keygen": print(json.dumps(keygen(a.private_key_file),sort_keys=True)); return 0
    if a.cmd=="public-key": print(json.dumps(export_public_key(a.private_key_file,a.public_key_file),sort_keys=True)); return 0
    store=StateStore(Path(a.database)); registry=ReviewerKeyRegistry(store)
    if a.cmd=="register":
        path=Path(a.public_key_file)
        if path.is_symlink(): raise ValueError("unsafe public key")
        raw=path.read_bytes()
        if len(raw)!=32: raise ValueError("public key must be 32 raw bytes")
        registry.register_reviewer_key(ReviewerPublicKey(a.key_id,a.reviewer_id,a.reviewer_provider,raw)); print("registered")
    elif a.cmd=="revoke": registry.revoke_reviewer_key(a.key_id,reason=a.reason); print("revoked")
    else:
        connection=store._connect()
        try: rows=connection.execute("SELECT key_id,reviewer_id,reviewer_provider,public_key,enabled,revoked FROM reviewer_keys ORDER BY key_id").fetchall()
        finally: connection.close()
        print(json.dumps([{"key_id":r[0],"reviewer_id":r[1],"reviewer_provider":r[2],"fingerprint_sha256":hashlib.sha256(bytes(r[3])).hexdigest(),"enabled":bool(r[4]),"revoked":bool(r[5])} for r in rows],sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
