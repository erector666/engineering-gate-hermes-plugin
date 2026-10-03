"""Reviewer Service v1 local UDS contract and Stage-2 rejection checks."""
from __future__ import annotations
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERMES = Path(os.environ["HERMES_SOURCE_ROOT"]) if os.environ.get("HERMES_SOURCE_ROOT") else Path(__import__("hermes_cli").__file__).resolve().parents[1]
PYTHON = sys.executable


def test_signed_rejection_is_terminal_and_never_writes(tmp_path):
    script = r'''
from stage2_dispatch_harness import create_harness
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from engineering_gate_core.mutation_authority import ReviewerKeyRegistry
from engineering_gate_core.signed_authorization import ReviewerPublicKey, SignedMutationVerdict, canonical_signed_verdict, DOMAIN_PREFIX
from engineering_gate_core.workflow import canonical_mutation_proposal_digest
from datetime import datetime, timezone
h=create_harness()
signed_module=h.core_module('signed_authorization')
workflow_module=h.core_module('workflow')
try:
 private=Ed25519PrivateKey.generate()
 public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
 ReviewerKeyRegistry(h.fixture.store).register_reviewer_key(ReviewerPublicKey('reject-key','rejecting-reviewer','test-provider',public))
 class RejectingReviewer:
  def __call__(self,task_id,proposal):
   state=h.fixture.store.load(task_id)
   payload={'schema_version':1,'signature_algorithm':'Ed25519','key_id':'reject-key',
    'review_id':'stage2-reject-review','reviewer_id':'rejecting-reviewer','reviewer_provider':'test-provider',
    'implementer_id':'engineering-gate-hermes','task_id':task_id,'plan_revision':int(state.revision),
    'plan_digest':str(state.plan_digest),'proposal_digest':workflow_module.canonical_mutation_proposal_digest(proposal),
    'verdict':'reject','reviewed_at':datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')}
   encoded=signed_module.canonical_signed_verdict(payload)
   return signed_module.SignedMutationVerdict(encoded,private.sign(signed_module.DOMAIN_PREFIX+encoded))
 h.set_provider(RejectingReviewer())
 out=h.dispatch()
 state=h.fixture.store.load('task-stage2')
 assert 'Gate write authorization is unavailable' in out,(out,getattr(h.adapter,'_last_error',None))
 assert state.state.value=='rejected',state.state
 assert not (h.workspace/'B').exists(),('unexpected file write',h.native_calls,out)
 assert h.native_calls==[],('native fallback',h.native_calls,out)
 assert h.fixture.store.list_execution_audits('task-stage2')==()
finally: h.close()
'''
    env=os.environ.copy()
    env.update(HERMES_HOME=str(tmp_path/'profile'), WORKSPACE=str(tmp_path/'workspace'), PLUGIN_PATH=str(ROOT/'engineering-gate'),
               PYTHONPATH=os.pathsep.join((str(ROOT/'engineering-gate'),str(ROOT/'tests/hermes_v0214'),str(HERMES))))
    result=subprocess.run([str(PYTHON),'-c',script],env=env,text=True,capture_output=True,timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
