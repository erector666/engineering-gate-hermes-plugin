"""Real Hermes-to-review-service-to-Gate WRITE path using synthetic local model output."""
from __future__ import annotations
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERMES = Path(os.environ["HERMES_SOURCE_ROOT"]) if os.environ.get("HERMES_SOURCE_ROOT") else Path(__import__("hermes_cli").__file__).resolve().parents[1]
PYTHON = sys.executable


def test_real_reviewer_process_authorizes_gate_owned_write_with_local_transport(tmp_path):
    script = r"""
import base64, json, os, socket, subprocess, sys, tempfile, time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from engineering_gate_core.mutation_authority import ReviewerKeyRegistry
from engineering_gate_core.signed_authorization import ReviewerPublicKey
from stage2_dispatch_harness import create_harness
from adapters.hermes.reviewer_service import ReviewerServiceClient
h=create_harness(final_path='B')
child=None
sock=None
socket_dir=None
try:
    private=Ed25519PrivateKey.generate()
    public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    ReviewerKeyRegistry(h.fixture.store).register_reviewer_key(
        ReviewerPublicKey('e2e-key','engineering-gate-reviewer-v1','openai:gpt-6.1-sol',public))
    socket_dir=Path(tempfile.mkdtemp(prefix='gate-review-'))
    sock=socket_dir/'s'
    keyfile=Path(os.environ['WORKSPACE'])/'review.key'
    keyfile.write_bytes(private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()))
    keyfile.chmod(0o600)
    svc=r'''
import json,os,sys
from pathlib import Path
from reviewer_service.service import serve,decide_and_sign,Ledger
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
sock,key,ledger=sys.argv[1:]
raw=Path(key).read_bytes()
priv=Ed25519PrivateKey.from_private_bytes(raw)
def synthetic(body):
    Path(ledger+'.body').write_text(json.dumps(body,sort_keys=True))
    # Local deterministic stand-in: only approve when exact bound write content is present.
    request_text=body['input'][1]['content'][0]['text']
    obj=json.loads(request_text)
    try:
        assert obj['proposal']['operation']['target']=='B'
        assert obj['mutation_arguments']['content']=='approved bytes'
        return {'status':'completed','model':'gpt-6.1-sol','output':[{'type':'message','status':'completed','content':[{'type':'output_text','text':'{"decision":"approve","findings":[]}'}]}], 'usage':{'input_tokens':42,'output_tokens':7}}
    except Exception as exc:
        Path(ledger+'.modelerr').write_text(repr(exc))
        raise
ledger_obj=Ledger(ledger)
def handle(req):
    try:
        Path(ledger+'.request').write_text(json.dumps(req,sort_keys=True))
        assert 'verdict' not in req
        return decide_and_sign(req,transport=synthetic,private_key=raw,key_id='e2e-key',ledger=ledger_obj)
    except Exception as exc:
        Path(ledger+'.err').write_text(repr(exc))
        raise
serve(sock,handle,authorized_uid=os.getuid(),socket_gid=os.getgid(),socket_mode=0o660)
'''
    child=subprocess.Popen([sys.executable,'-c',svc,str(sock),str(keyfile),str(Path(os.environ['WORKSPACE'])/'ledger.sqlite')],env=os.environ.copy(),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        if child.poll() is not None: raise AssertionError('review service exited: '+child.stderr.read().decode())
        if sock.exists(): break
        time.sleep(.03)
    assert sock.exists(),'service UDS did not become ready'
    service_source=Path(os.environ['PLUGIN_PATH']).parent/'engineering-gate'/'reviewer_service'/'service.py'
    # The actual child imports the same production service module; its injected transport is local-only.
    import importlib
    plugin_name=h.manager._plugins['engineering-gate'].module.__name__
    ReviewerServiceClient=importlib.import_module(plugin_name+'.adapters.hermes.reviewer_service').ReviewerServiceClient
    client=ReviewerServiceClient(str(sock),key_id='e2e-key').bind_store(h.fixture.store)
    client._reviewer_service_v1=True
    h.set_provider(client)
    out=h.dispatch(); result=json.loads(out)
    assert result.get('gate_owned') is True,(result,getattr(h.adapter,'_last_error',None),(Path(str(Path(os.environ['WORKSPACE'])/'ledger.sqlite')+'.err').read_text() if Path(str(Path(os.environ['WORKSPACE'])/'ledger.sqlite')+'.err').exists() else None),(Path(str(Path(os.environ['WORKSPACE'])/'ledger.sqlite')+'.body').read_text() if Path(str(Path(os.environ['WORKSPACE'])/'ledger.sqlite')+'.body').exists() else None))
    assert h.intercepted[-1][1]=={'path':'B','content':'approved bytes'}
    assert not h.native_calls
    assert (h.workspace/'B').read_bytes()==b'approved bytes'
    state=h.fixture.store.load('task-stage2')
    assert state.state.value=='verifying',state.state
    audits=h.fixture.store.list_execution_audits('task-stage2'); assert len(audits)==1,audits
    assert all(item.passed for item in state.verification),state.verification
    request_record=Path(str(Path(os.environ['WORKSPACE'])/'ledger.sqlite')+'.request')
    request=json.loads(request_record.read_text())
    assert set(request)=={'schema_version','review_request_id','task_id','plan_revision','plan_digest','approval_packet','approval_packet_digest','proposal','proposal_digest','mutation_arguments','implementer_id'}
    assert 'verdict' not in request
    assert 'api.openai.com' not in os.environ.get('HTTP_PROXY','')
    # Explicit limitation: service and Gate run as the same OS UID in this test.
finally:
    h.close()
    if child:
        child.terminate()
        try: child.wait(timeout=3)
        except subprocess.TimeoutExpired: child.kill(); child.wait()
    if sock is not None and sock.exists(): sock.unlink()
    if socket_dir is not None: socket_dir.rmdir()
"""
    env=os.environ.copy()
    env.update(HERMES_HOME=str(tmp_path/'profile'),WORKSPACE=str(tmp_path/'workspace'),PLUGIN_PATH=str(ROOT/'engineering-gate'),
               PYTHONPATH=os.pathsep.join((str(ROOT/'engineering-gate'),str(ROOT/'tests/hermes_v0214'),str(HERMES))))
    result=subprocess.run([str(PYTHON),'-c',script],env=env,text=True,capture_output=True,timeout=60)
    assert result.returncode==0,result.stdout+result.stderr
