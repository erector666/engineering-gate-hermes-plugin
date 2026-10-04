"""Strict one-shot reviewer-client failures over real temporary Unix sockets."""
from __future__ import annotations

import base64
import json
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path

from adapters.hermes.reviewer_service import ReviewerServiceClient


ROOT = Path(__file__).resolve().parents[2]
HERMES = Path(os.environ["HERMES_SOURCE_ROOT"]) if os.environ.get("HERMES_SOURCE_ROOT") else Path(__import__("hermes_cli").__file__).resolve().parents[1]
PYTHON = sys.executable


def test_client_timeout_covers_service_deadline_with_margin():
    client = ReviewerServiceClient("reviewer.sock", key_id="test", reviewer_provider="openai:gpt-6.1-sol")
    assert client.timeout >= 75
    try:
        ReviewerServiceClient("reviewer.sock", key_id="test", reviewer_provider="openai:gpt-6.1-sol", timeout=74.99)
    except ValueError:
        pass
    else:
        raise AssertionError("client accepted timeout shorter than service deadline plus margin")


def test_reviewer_client_failure_matrix_and_one_shot_fail_closed(tmp_path):
    # Run against the test interpreter and pinned Gate core; no host plugin manager.
    script = r'''
import base64,json,socket,struct,threading
from datetime import datetime,timedelta,timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from engineering_gate_core.models import MutationProposal,OperationKind,NormalizedOperation
from engineering_gate_core.workflow import mutation_argument_digest,canonical_mutation_proposal_digest
from engineering_gate_core.signed_authorization import ReviewerPublicKey,AuthorizationTimingPolicy,DOMAIN_PREFIX,canonical_signed_verdict
from adapters.hermes.reviewer_service import ReviewerServiceClient,MAX_FRAME
import uuid

class Store:
 def __init__(self,keys): self.keys=keys; self.timing_policy=AuthorizationTimingPolicy(300,300)
 def get_reviewer_key(self,key_id):
  key=self.keys.get(key_id)
  if key is None: raise KeyError(key_id)
  return key

private=Ed25519PrivateKey.generate(); public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
providers={'client-key':'openai:gpt-6.1-sol','alternate-key':'anthropic:claude-reviewer'}
keys={k:ReviewerPublicKey(k,'engineering-gate-reviewer-v1',v,public) for k,v in providers.items()}
# Minimal real Gate state/proposal fixture: dataclasses from core, no host fixture/plugin loading.
from types import SimpleNamespace
operation=NormalizedOperation(OperationKind.WRITE,'src/reviewed.txt','test rationale')
state=SimpleNamespace(revision=7,plan_digest='a'*64)
proposal=MutationProposal('proposal-1','task-stage2',state.revision,state.plan_digest,operation,mutation_argument_digest('approved bytes'),'test')
digest=canonical_mutation_proposal_digest(proposal)

def payload(key_id='client-key', **change):
 d={'schema_version':1,'signature_algorithm':'Ed25519','key_id':key_id,'review_id':'client-review','reviewer_id':'engineering-gate-reviewer-v1','reviewer_provider':providers.get(key_id,'openai:gpt-6.1-sol'),'implementer_id':'engineering-gate-hermes','task_id':'task-stage2','plan_revision':state.revision,'plan_digest':state.plan_digest,'proposal_digest':digest,'verdict':'approve','reviewed_at':datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')}; d.update(change); return d
def signed(p):
 raw=canonical_signed_verdict(p); return {'canonical_payload_b64':base64.b64encode(raw).decode(),'signature_b64':base64.b64encode(private.sign(DOMAIN_PREFIX+raw)).decode()}
def frame(obj):
 b=obj if isinstance(obj,bytes) else json.dumps(obj,separators=(',',':')).encode(); return struct.pack('!I',len(b))+b
def invoke(reply, *, key_id='client-key', reviewer_provider='openai:gpt-6.1-sol', timeout=1, store_keys=None):
 import tempfile
 path=Path(tempfile.mkdtemp(prefix='review-client-'))/'s'; seen=[]; requests=[]; ready=threading.Event()
 def server():
  s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind(str(path)); s.listen(5); s.settimeout(1); ready.set()
  try:
   c,_=s.accept(); seen.append(1); c.settimeout(2)
   try:
    hdr=c.recv(4)
    if len(hdr)==4:
     size=struct.unpack('!I',hdr)[0]; data=b''
     while len(data)<size:
      chunk=c.recv(size-len(data))
      if not chunk: break
      data+=chunk
     if len(data)==size: requests.append(json.loads(data));
     if reply is not None: reply(c)
   except (OSError,TimeoutError): pass
   finally: c.close()
  except socket.timeout: pass
  finally: s.close()
 t=threading.Thread(target=server,daemon=True); t.start(); ready.wait(2)
 client=ReviewerServiceClient(str(path),key_id=key_id,reviewer_provider=reviewer_provider).bind_store(Store(keys if store_keys is None else store_keys)); client.timeout=timeout
 try: result=client('task-stage2',proposal,state=state,approval_packet='{}',approval_packet_digest='x',content='x'); error=None
 except Exception as exc: result=None; error=exc
 t.join(3)
 try: path.unlink(); path.parent.rmdir()
 except OSError: pass
 return result,error,len(seen),requests

def send(obj): return lambda c:c.sendall(obj if isinstance(obj,bytes) else frame(obj))
# Alternate providers remain valid for Gate's fixed reviewer identity.
r,e,n,req=invoke(send(frame(signed(payload('alternate-key')))),key_id='alternate-key',reviewer_provider='anthropic:claude-reviewer'); assert e is None and r and n==1,(e,n)
assert len(req)==1 and not ({'reviewer_provider','model','reviewer_model'} & req[0].keys()),req
# A registered key for another provider cannot override the active config's exact identity.
r,e,n,_=invoke(send(frame(signed(payload('alternate-key')))),key_id='alternate-key',reviewer_provider='openai:gpt-6.1-sol'); assert e is not None and n==1,(e,n)
# A correctly signed, registered key cannot redefine Gate's reviewer identity.
wrong_id='other-reviewer'
wrong_key=ReviewerPublicKey('wrong-reviewer-key',wrong_id,providers['client-key'],public)
r,e,n,_=invoke(send(frame(signed(payload('wrong-reviewer-key',reviewer_id=wrong_id)))),key_id='wrong-reviewer-key',store_keys={'wrong-reviewer-key':wrong_key})
assert e is not None and n==1,(e,n)
# Malformed wire/frame variants.
for wire in [frame({'canonical_payload_b64':'','signature_b64':'','extra':1}),struct.pack('!I',40)+b'{"x":',struct.pack('!I',MAX_FRAME+1),frame(signed(payload()))+b'x',b'\x00\x00\x00\x02{}',b'\x00\x00\x00\x3d{"canonical_payload_b64":"","signature_b64":"","signature_b64":"","x":1}']:
 r,e,n,_=invoke(lambda c,w=wire:c.sendall(w)); assert e is not None and n==1,(wire,e,n)
# Correctly signed binding failures.
for change in [{'key_id':'other-key'},{'reviewer_id':'other-reviewer'},{'reviewer_provider':'other-provider'},{'implementer_id':'other-implementer'},{'task_id':'other-task'},{'plan_revision':state.revision+1},{'plan_digest':'0'*64},{'proposal_digest':'0'*64},{'reviewed_at':(datetime.now(timezone.utc)-timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')},{'reviewed_at':(datetime.now(timezone.utc)+timedelta(minutes=2)).strftime('%Y-%m-%dT%H:%M:%SZ')}]:
 r,e,n,_=invoke(send(frame(signed(payload(**change))))); assert e is not None and n==1,(change,e,n)
def bad(c):
 obj=signed(payload()); obj['signature_b64']=base64.b64encode(b'\0'*64).decode(); c.sendall(frame(obj))
r,e,n,_=invoke(bad); assert e is not None and n==1
# Disabled, revoked, and absent key records fail closed.
for k in [ReviewerPublicKey('disabled','engineering-gate-reviewer-v1',providers['client-key'],public,enabled=False),ReviewerPublicKey('revoked','engineering-gate-reviewer-v1',providers['client-key'],public,revoked=True)]:
 r,e,n,_=invoke(send(frame(signed(payload(key_id=k.key_id)))),key_id=k.key_id,store_keys={k.key_id:k}); assert e is not None and n==1,(k,e,n)
r,e,n,_=invoke(send(frame(signed(payload()))),key_id='missing'); assert e is not None and n==1
# Silent connected service times out once; server only accepts one client.
r,e,n,_=invoke(None,timeout=.1); assert e is not None and n==1,(e,n)
'''
    env = os.environ.copy()
    env.update(HERMES_HOME=str(tmp_path / "profile"), WORKSPACE=str(tmp_path / "workspace"),
               PYTHONPATH=os.pathsep.join((str(ROOT / "engineering-gate"), str(HERMES))))
    result = subprocess.run([str(PYTHON), "-c", script], env=env, text=True, capture_output=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
