"""Pinned-Hermes dispatch regressions for reviewer and Gate failure paths."""
from __future__ import annotations
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERMES = Path("/home/uss/.hermes/cache/scratch/hermes-v0214-execution-interception")
PYTHON = Path("/home/uss/.hermes/hermes-agent/venv/bin/python")

CASES = {
"invalid_signature": r'''
from engineering_gate_core.signed_authorization import SignedMutationVerdict
h=create_harness();
try:
 def invalid(task, proposal):
  good=h.provider(task,proposal)
  return SignedMutationVerdict(good.canonical_payload, b'\0'*64)
 h.set_provider(invalid); out=h.dispatch()
 assert 'Gate write authorization is unavailable' in out,(out,getattr(h.adapter,'_last_error',None))
 assert not (h.workspace/'B').exists(); assert h.native_calls==[]
 assert h.fixture.store.load('task-stage2').state.value=='failed'
 assert h.fixture.store.load('task-stage2').mutation_proposal is not None
 assert not h.fixture.store.list_execution_audits('task-stage2')
 assert h.provider.used, ('signed reviewer provider was not invoked',h.adapter._last_error)
finally: h.close()
''',
"revoked_key": r'''
from engineering_gate_core.mutation_authority import ReviewerKeyRegistry
h=create_harness();
try:
 ReviewerKeyRegistry(h.fixture.store).revoke_reviewer_key('stage2-key',reason='test revocation')
 h.set_provider(h.provider); out=h.dispatch()
 assert 'Gate write authorization is unavailable' in out,(out,getattr(h.adapter,'_last_error',None))
 assert h.provider.used; assert not (h.workspace/'B').exists(); assert h.native_calls==[]
 assert not h.fixture.store.list_execution_audits('task-stage2')
finally: h.close()
''',
"expired_authorization": r'''
from datetime import datetime,timedelta,timezone
h=create_harness();
try:
 GateMutationAuthority=h.core_module('mutation_authority').GateMutationAuthority
 h.set_provider(h.provider); calls=[]
 def clock(self):
  calls.append(1)
  return datetime.now(timezone.utc) if len(calls)==1 else datetime.now(timezone.utc)+timedelta(days=2)
 GateMutationAuthority._now=clock
 out=h.dispatch(); state=h.fixture.store.load('task-stage2')
 assert 'Gate write authorization is unavailable' in out,(out,getattr(h.adapter,'_last_error',None))
 assert h.provider.used and len(calls)>=2,calls
 assert not (h.workspace/'B').exists() and h.native_calls==[]
 connection=h.fixture.store._connect()
 try: lease_row=connection.execute('SELECT authorization_id,status,expires_at FROM mutation_leases ORDER BY rowid DESC LIMIT 1').fetchone()
 finally: connection.close()
 assert lease_row is not None and lease_row[1]=='ACTIVE',lease_row
 assert lease_row[2] < (datetime.now(timezone.utc)+timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%SZ'),lease_row
finally: h.close()
''',
"adapter_exception": r'''
h=create_harness();
try:
 h.adapter._execute_inner=lambda *a,**k: (_ for _ in ()).throw(RuntimeError('injected adapter failure'))
 out=h.dispatch(); state=h.fixture.store.load('task-stage2')
 assert '"error"' in out.lower() and h.adapter._last_error,(out,h.adapter._last_error,state)
 assert state.state.value=='approved'
 assert state.mutation_proposal is None
 assert not (h.workspace/'B').exists() and h.native_calls==[]
 assert not h.fixture.store.list_execution_audits('task-stage2')
finally: h.close()
''',
"replace_failure": r'''
import engineering_gate_core.a3_execution as execution
h=create_harness();
try:
 h.set_provider(h.provider); original=execution.os.replace
 def fail(*a,**k): raise OSError('injected replace failure')
 execution.os.replace=fail
 try: out=h.dispatch()
 finally: execution.os.replace=original
 assert 'gate_owned' not in out,(out,h.adapter._last_error)
 assert h.provider.used and not (h.workspace/'B').exists() and h.native_calls==[]
 connection=h.fixture.store._connect()
 try: lease_row=connection.execute('SELECT authorization_id,status FROM mutation_leases ORDER BY rowid DESC LIMIT 1').fetchone()
 finally: connection.close()
 assert lease_row is not None and lease_row[1]=='CONSUMED_UNCERTAIN',lease_row
 auth=h.fixture.store.get_authorization(lease_row[0])
 assert auth and auth.status.value=='CONSUMED_UNCERTAIN',auth
finally: h.close()
''',
"expired_stage1_approval": r'''
import json,time
h=create_harness();
try:
 with h.sidecar._db('default') as db:
  row=db.execute('SELECT data FROM approvals WHERE nonce=?',(h._record_id,)).fetchone(); record=json.loads(row[0]); record['created_at']=time.time()-3600; record['expires_at']=time.time()-1
  db.execute('UPDATE approvals SET data=? WHERE nonce=?',(json.dumps(record,sort_keys=True,separators=(',',':')),h._record_id))
 h.set_provider(h.provider); out=h.dispatch()
 assert 'Gate write authorization is unavailable' in out,(out,getattr(h.adapter,'_last_error',None))
 assert not (h.workspace/'B').exists() and h.native_calls==[] and not h.provider.used
 assert h.fixture.store.load('task-stage2').state.value=='approved'
finally: h.close()
''',
"provider_exception_state": r'''
h=create_harness();
try:
 def fail(task,proposal): raise RuntimeError('review provider unavailable')
 h.set_provider(fail); out=h.dispatch(); state=h.fixture.store.load('task-stage2')
 assert 'Gate write authorization is unavailable' in out,(out,getattr(h.adapter,'_last_error',None))
 assert state.state.value=='failed',state.state
 assert state.mutation_proposal is not None and not (h.workspace/'B').exists() and h.native_calls==[]
finally: h.close()
''',
"verification_failure_after_commit": r'''
import json
h=create_harness();
try:
 GateVerificationRunner=h.core_module('verification_execution').GateVerificationRunner
 h.set_provider(h.provider); original=GateVerificationRunner.run_all
 GateVerificationRunner.run_all=lambda self,task_id: (_ for _ in ()).throw(RuntimeError('verify unavailable'))
 try: out=h.dispatch()
 finally: GateVerificationRunner.run_all=original
 assert json.loads(out)=={'gate_owned':True,'target':'B','bytes':len(b'approved bytes'),\
  'write_committed':True,'verification':'failed','further_mutation':'blocked'},(out,h.adapter._last_error)
 assert (h.workspace/'B').read_bytes()==b'approved bytes' and h.native_calls==[]
 audits=h.fixture.store.list_execution_audits('task-stage2'); assert len(audits)==1,audits
 connection=h.fixture.store._connect()
 try: lease=connection.execute('SELECT status FROM mutation_leases ORDER BY rowid DESC LIMIT 1').fetchone()
 finally: connection.close()
 assert lease and lease[0]=='CONSUMED',lease
 assert h.sidecar.find_unique_approved('default','task-stage2',h.fixture.request.request_id)['state']=='approved'
finally: h.close()
''',
"readback_failure": r'''
import engineering_gate_core.a3_execution as execution
h=create_harness();
try:
 h.set_provider(h.provider); original=execution.os.open
 def fail_readback(path, flags, *a, **k):
  if path=='B' and k.get('dir_fd') is not None: raise OSError('injected readback failure')
  return original(path,flags,*a,**k)
 execution.os.open=fail_readback
 try: out=h.dispatch()
 finally: execution.os.open=original
 assert 'gate_owned' not in out,(out,h.adapter._last_error)
 assert h.provider.used and h.native_calls==[]
 audits=h.fixture.store.list_execution_audits('task-stage2'); assert len(audits)==1,audits
 audit=audits[0]
 assert audit.outcome.value=='outcome_unknown' and audit.resulting_artifact_digest is None,audit
 assert (h.workspace/'B').exists() and (h.workspace/'B').read_bytes()==b'approved bytes'
 auth=h.fixture.store.get_authorization(audit.authorization_id)
 assert auth.status.value=='CONSUMED_UNCERTAIN',auth
finally: h.close()
'''
}


def test_reviewer_and_gate_failures_block_real_pinned_dispatch(tmp_path):
    for name, body in CASES.items():
        script = "from stage2_dispatch_harness import create_harness\n" + body
        env=os.environ.copy()
        env.update(HERMES_HOME=str(tmp_path/name/'profile'), WORKSPACE=str(tmp_path/name/'workspace'),
                   PLUGIN_PATH=str(ROOT/'engineering-gate'),
                   PYTHONPATH=os.pathsep.join((str(ROOT/'engineering-gate'),str(ROOT/'tests/hermes_v0214'),str(HERMES))))
        result=subprocess.run([str(PYTHON),'-c',script],env=env,text=True,capture_output=True,timeout=60)
        assert result.returncode==0, f'{name}: {result.stdout}{result.stderr}'
