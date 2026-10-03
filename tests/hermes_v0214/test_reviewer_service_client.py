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


def test_client_timeout_covers_service_deadline_with_margin():
    client = ReviewerServiceClient("reviewer.sock", key_id="test")
    assert client.timeout >= 75
    try:
        ReviewerServiceClient("reviewer.sock", key_id="test", timeout=74.99)
    except ValueError:
        pass
    else:
        raise AssertionError("client accepted timeout shorter than service deadline plus margin")


ROOT = Path(__file__).resolve().parents[2]
HERMES = Path(os.environ["HERMES_SOURCE_ROOT"]) if os.environ.get("HERMES_SOURCE_ROOT") else Path(__import__("hermes_cli").__file__).resolve().parents[1]
PYTHON = sys.executable


def test_reviewer_client_failure_matrix_and_one_shot_fail_closed(tmp_path):
    script = r'''
import base64,json,os,socket,struct,threading,tempfile
from datetime import datetime,timedelta,timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from engineering_gate_core.mutation_authority import ReviewerKeyRegistry
from engineering_gate_core.signed_authorization import ReviewerPublicKey,DOMAIN_PREFIX,canonical_signed_verdict
from adapters.hermes.reviewer_service import ReviewerServiceClient,MAX_FRAME
from stage2_dispatch_harness import create_harness
h=create_harness()
private=Ed25519PrivateKey.generate(); public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
registry=ReviewerKeyRegistry(h.fixture.store)
registry.register_reviewer_key(ReviewerPublicKey('client-key','engineering-gate-reviewer-v1','openai:gpt-6.1-sol',public))
import uuid
from engineering_gate_core.models import MutationProposal,OperationKind
from engineering_gate_core.workflow import mutation_argument_digest
state=h.fixture.store.load('task-stage2'); operation=next(op for op in state.plan.operations if op.kind is OperationKind.WRITE)
proposal=MutationProposal(uuid.uuid4().hex,state.task_id,state.revision,state.plan_digest,operation,mutation_argument_digest('approved bytes'),'test')
workflow=h.core_module('workflow'); digest=workflow.canonical_mutation_proposal_digest(proposal)
def payload(**change):
 d={'schema_version':1,'signature_algorithm':'Ed25519','key_id':'client-key','review_id':'client-review','reviewer_id':'engineering-gate-reviewer-v1','reviewer_provider':'openai:gpt-6.1-sol','implementer_id':'engineering-gate-hermes','task_id':'task-stage2','plan_revision':int(state.revision),'plan_digest':str(state.plan_digest),'proposal_digest':digest,'verdict':'approve','reviewed_at':datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')}; d.update(change); return d
def signed(p):
 raw=canonical_signed_verdict(p); return {'canonical_payload_b64':base64.b64encode(raw).decode(),'signature_b64':base64.b64encode(private.sign(DOMAIN_PREFIX+raw)).decode()}
def frame(obj):
 b=obj if isinstance(obj,bytes) else json.dumps(obj,separators=(',',':')).encode(); return struct.pack('!I',len(b))+b
def invoke(raw, *, absent=False, timeout=.3, client_key='client-key'):
 path=Path(tempfile.mkdtemp(prefix='review-client-'))/'s'
 seen=[]; ready=threading.Event()
 def server():
  s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind(str(path)); s.listen(2); s.settimeout(1); ready.set()
  try:
   if absent: return
   c,_=s.accept(); seen.append(1); c.settimeout(1)
   try:
    hdr=c.recv(4)
    if len(hdr)==4:
     size=struct.unpack('!I',hdr)[0]; left=size
     while left:
      chunk=c.recv(left)
      if not chunk: break
      left-=len(chunk)
     if not callable(raw): c.sendall(raw)
     else: raw(c)
   except (OSError,TimeoutError): pass
   finally: c.close()
  finally: s.close()
 t=threading.Thread(target=server,daemon=True); t.start(); ready.wait(2)
 client=ReviewerServiceClient(str(path),key_id=client_key).bind_store(h.fixture.store)
 # Test-only seam: preserve fast simulated timeout cases without weakening production validation.
 client.timeout=timeout
 try:
  result=client('task-stage2',proposal,state=state,approval_packet='{}',approval_packet_digest='x',content='x')
  error=None
 except Exception as exc: result=None; error=exc
 t.join(2)
 try: path.unlink()
 except FileNotFoundError: pass
 path.parent.rmdir()
 return result,error,len(seen)
def ok_reply(c): c.sendall(frame(signed(payload())))
r,e,n=invoke(ok_reply); assert e is None and r and n==1,(e,n)
# Strict outer schema, duplicate keys, base64, and framing violations.
for wire in [frame({'canonical_payload_b64':'','signature_b64':'','extra':1}),struct.pack('!I',40)+b'{"x":',struct.pack('!I',MAX_FRAME+1),frame(signed(payload()))+b'x',b'\x00\x00\x00\x02{}',b'\x00\x00\x00\x1f{"canonical_payload_b64":"!","signature_b64":""}',b'\x00\x00\x00\x3d{"canonical_payload_b64":"","signature_b64":"","signature_b64":""}']:
 r,e,n=invoke(wire); assert e is not None and n==1,(wire,e,n)
# All semantic mismatches carry valid signatures, so failures test client bindings.
for change in [{'key_id':'other-key'},{'reviewer_id':'other-reviewer'},{'reviewer_provider':'other-provider'},{'implementer_id':'other-implementer'},{'task_id':'other-task'},{'plan_revision':int(state.revision)+1},{'plan_digest':'0'*64},{'proposal_digest':'0'*64},{'reviewed_at':(datetime.now(timezone.utc)-timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')},{'reviewed_at':(datetime.now(timezone.utc)+timedelta(minutes=2)).strftime('%Y-%m-%dT%H:%M:%SZ')}]:
 r,e,n=invoke(lambda c,ch=change:c.sendall(frame(signed(payload(**ch))))); assert e is not None and n==1,(change,e,n)
# Signature corruption while keeping otherwise valid response.
def bad_signature(c):
 obj=signed(payload()); obj['signature_b64']=base64.b64encode(b'\0'*64).decode(); c.sendall(frame(obj))
r,e,n=invoke(bad_signature); assert e is not None and n==1,(e,n)
registry.register_reviewer_key(ReviewerPublicKey('disabled-key','engineering-gate-reviewer-v1','openai:gpt-6.1-sol',public,enabled=False))
r,e,n=invoke(lambda c:c.sendall(frame(signed(payload(key_id='disabled-key')))),client_key='disabled-key'); assert e is not None and n==1,(e,n)
registry.register_reviewer_key(ReviewerPublicKey('revoked-key','engineering-gate-reviewer-v1','openai:gpt-6.1-sol',public)); registry.revoke_reviewer_key('revoked-key',reason='test')
r,e,n=invoke(lambda c:c.sendall(frame(signed(payload(key_id='revoked-key')))),client_key='revoked-key'); assert e is not None and n==1,(e,n)
r,e,n=invoke(b'',absent=True); assert e is not None and n==0,(e,n)
# A connected peer that never responds times out once; no reconnection occurs.
r,e,n=invoke(lambda c:None,timeout=.1); assert e is not None and n==1,(e,n)
# Missing key lookup is also closed after the single response.
r,e,n=invoke(ok_reply,client_key='not-registered'); assert e is not None and n==1,(e,n)
h.close()
'''
    env=os.environ.copy()
    env.update(HERMES_HOME=str(tmp_path/'profile'),WORKSPACE=str(tmp_path/'workspace'),PLUGIN_PATH=str(ROOT/'engineering-gate'),
               PYTHONPATH=os.pathsep.join((str(ROOT/'engineering-gate'),str(ROOT/'tests/hermes_v0214'),str(HERMES))))
    result=subprocess.run([str(PYTHON),'-c',script],env=env,text=True,capture_output=True,timeout=90)
    assert result.returncode==0,result.stdout+result.stderr
