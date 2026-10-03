"""Real Hermes dispatch contract for a Gate-owned Stage-2 write."""
from __future__ import annotations
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERMES = Path("/home/uss/.hermes/cache/scratch/hermes-v0214-execution-interception")
PYTHON = Path("/home/uss/.hermes/hermes-agent/venv/bin/python")


def test_approved_write_is_gate_owned_and_bound_to_final_rewritten_target(tmp_path):
    script = r'''
import hashlib, json
from engineering_gate_core.workflow import mutation_argument_digest, canonical_mutation_proposal_digest
from stage2_dispatch_harness import create_harness
h=create_harness(final_path='B')
try:
    # Missing provider denies before proposal, file creation, or native execution.
    blocked=h.dispatch()
    assert 'Gate write authorization is unavailable' in blocked,blocked
    assert not (h.workspace/'B').exists()
    assert h.fixture.store.load('task-stage2').mutation_proposal is None
    assert h.native_calls==[],h.native_calls

    h.set_provider(h.provider)
    # A mismatch in the persisted displayed-plan digest is rejected before review.
    h.tamper_packet_digest()
    denied=h.dispatch()
    assert 'Gate write authorization is unavailable' in denied,denied
    assert not (h.workspace/'B').exists()
    assert h.fixture.store.load('task-stage2').mutation_proposal is None
    assert not h.provider.used
    assert h.native_calls==[],h.native_calls
    h.restore_packet_digest()

    out=h.dispatch(); result=json.loads(out)
    assert result.get('gate_owned') is True,(result,getattr(h.adapter,'_last_error',None))
    assert h.native_calls==[],h.native_calls
    assert h.request_seen[-1]=={'path':'A','content':'approved bytes'}
    assert h.execution_seen[-1]=={'path':'A','content':'approved bytes'}
    assert h.intercepted[-1][1]=={'path':'B','content':'approved bytes'},h.intercepted
    assert h.intercepted[-1][2].get('task_id')=='task-stage2'
    assert h.intercepted[-1][2].get('session_id')==h.entry.session_id
    assert h.intercepted[-1][2].get('turn_id')=='turn-stage2'
    assert h.intercepted[-1][2].get('tool_call_id')=='call-stage2'
    assert (h.workspace/'B').read_bytes()==b'approved bytes'
    state=h.fixture.store.load('task-stage2'); proposal=state.mutation_proposal
    assert proposal is not None and proposal.operation.target=='B'
    assert proposal.argument_digest==mutation_argument_digest('approved bytes')
    audits=h.fixture.store.list_execution_audits('task-stage2'); assert len(audits)==1
    audit=audits[0]
    assert audit.task_id=='task-stage2' and audit.proposal_digest==canonical_mutation_proposal_digest(proposal)
    assert audit.authorization_id and h.fixture.store.get_authorization(audit.authorization_id).status.value=='CONSUMED'
    assert audit.target=='B' and audit.argument_digest==mutation_argument_digest('approved bytes')
    assert audit.resulting_artifact_digest==hashlib.sha256(b'approved bytes').hexdigest()
    verification=h.fixture.store.load('task-stage2').verification
    assert verification and all(item.passed for item in verification),verification
finally:
    h.close()
'''
    env=os.environ.copy()
    env.update(HERMES_HOME=str(tmp_path/'profile'), WORKSPACE=str(tmp_path/'workspace'), PLUGIN_PATH=str(ROOT/'engineering-gate'),
               PYTHONPATH=os.pathsep.join((str(ROOT/'engineering-gate'),str(ROOT/'tests/hermes_v0214'),str(HERMES))))
    result=subprocess.run([str(PYTHON),'-c',script],env=env,text=True,capture_output=True,timeout=60)
    assert result.returncode==0,result.stdout+result.stderr


def test_late_packet_change_blocks_before_gate_write(tmp_path):
    script = r'''
import dataclasses, importlib
from stage2_dispatch_harness import create_harness
h=create_harness(final_path='B')
try:
    h.set_provider(h.provider)
    core=h.core_module('state_store')
    models=h.core_module('models')
    original=core.StateStore.with_current_state_transaction
    injected=[False]
    def mutate_before_transaction(store, task_id, callback):
        if str(task_id)=='task-stage2' and not injected[0]:
            injected[0]=True
            connection=store._connect()
            try:
                row=connection.execute('SELECT payload FROM task_state WHERE task_id=?',(str(task_id),)).fetchone()
                current=core._record_from_json(row[0])
                altered=dataclasses.replace(current, analysis=models.Evidence(
                    evidence_id='approval-packet-race', description='changed after adapter recheck'))
                connection.execute('UPDATE task_state SET payload=? WHERE task_id=?',
                                   (core._record_json(altered),str(task_id)))
                connection.commit()
            finally:
                connection.close()
        return original(store, task_id, callback)
    core.StateStore.with_current_state_transaction=mutate_before_transaction
    denied=h.dispatch()
    core.StateStore.with_current_state_transaction=original
    persisted=h.fixture.store.load('task-stage2')
    assert injected[0], 'race injection did not reach Gate transaction boundary'
    assert persisted.analysis is not None and persisted.analysis.evidence_id=='approval-packet-race', persisted.analysis
    assert 'Gate write authorization is unavailable' in denied, (
        'approval packet changed after adapter outer recheck, but WRITE was not denied: '+denied)
    assert not (h.workspace/'B').exists(), 'approved bytes were written despite changed packet'
    assert not h.native_calls, 'native write occurred despite changed packet: '+repr(h.native_calls)
finally:
    h.close()
'''
    env=os.environ.copy()
    env.update(HERMES_HOME=str(tmp_path/'profile'), WORKSPACE=str(tmp_path/'workspace'), PLUGIN_PATH=str(ROOT/'engineering-gate'),
               PYTHONPATH=os.pathsep.join((str(ROOT/'engineering-gate'),str(ROOT/'tests/hermes_v0214'),str(HERMES))))
    result=subprocess.run([str(PYTHON),'-c',script],env=env,text=True,capture_output=True,timeout=60)
    assert result.returncode==0,result.stdout+result.stderr
