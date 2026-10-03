"""Disposable real-Hermes Stage-2 dispatch harness for subprocess tests."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hermes_cli.plugins import get_plugin_manager
from hermes_cli.plugins_manifest import PluginManifest
from tools.registry import registry
import model_tools
from stage2_fixture import seed_approved_fixture
from gateway.config import GatewayConfig, PlatformConfig, Platform
from gateway.session import SessionSource, SessionStore
from plugins.platforms.telegram.adapter import TelegramAdapter
from gateway import session_context
from tools import approval_context
from engineering_gate_core.mutation_authority import ReviewerKeyRegistry
from engineering_gate_core.models import OperationKind
from engineering_gate_core.workflow import mutation_argument_digest, canonical_mutation_proposal_digest
from engineering_gate_core.signed_authorization import (
    ReviewerPublicKey, SignedMutationVerdict, DOMAIN_PREFIX, canonical_signed_verdict,
)


@dataclass
class DispatchHarness:
    home: Path
    workspace: Path
    routes: SessionStore
    entry: object
    fixture: object
    manager: object
    adapter: object
    provider: object
    request_seen: list
    execution_seen: list
    intercepted: list
    native_calls: list
    _write_entry: object
    _native_handler: object
    _sidecar_db: object
    _record_id: str
    _original_display_digest: str

    @property
    def sidecar(self):
        return self.adapter.approval_sidecar

    def set_provider(self, provider):
        """Set reviewer provider only on the loaded adapter instance."""
        self.adapter._reviewer_verdict_provider = provider

    def core_module(self, module):
        """Import a Gate core module from the namespace loaded by Hermes."""
        import importlib
        return importlib.import_module(
            self.manager._plugins['engineering-gate'].module.__name__
            + '.engineering_gate_core.' + module
        )

    def tamper_display_digest(self):
        with self.sidecar._db('default') as db:
            row = db.execute('SELECT data FROM approvals WHERE nonce=?', (self._record_id,)).fetchone()
            record = json.loads(row[0])
            record['plan_display_digest'] = '0' * 64 if self._original_display_digest != '0' * 64 else '1' * 64
            db.execute('UPDATE approvals SET data=? WHERE nonce=?',
                       (json.dumps(record, sort_keys=True, separators=(',', ':')), self._record_id))

    def restore_display_digest(self):
        with self.sidecar._db('default') as db:
            row = db.execute('SELECT data FROM approvals WHERE nonce=?', (self._record_id,)).fetchone()
            record = json.loads(row[0])
            record['plan_display_digest'] = self._original_display_digest
            db.execute('UPDATE approvals SET data=? WHERE nonce=?',
                       (json.dumps(record, sort_keys=True, separators=(',', ':')), self._record_id))
        restored = self.sidecar.find_unique_approved('default', 'task-stage2', self.fixture.request.request_id)
        assert restored['plan_display_digest'] == self._original_display_digest

    def dispatch(self, args=None):
        return model_tools.handle_function_call(
            'write_file', args or {'path': 'A', 'content': 'approved bytes'},
            task_id='task-stage2', session_id=self.entry.session_id, turn_id='turn-stage2',
            tool_call_id='call-stage2', api_request_id='request-stage2')

    def close(self):
        self._write_entry.handler = self._native_handler


def create_harness(*, final_path='B'):
    """Build one isolated fixture; call only inside a pinned-Hermes subprocess."""
    home = Path(os.environ['HERMES_HOME']); home.mkdir(mode=0o700, parents=True, exist_ok=True)
    workspace = Path(os.environ['WORKSPACE']); workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    routes = SessionStore(home / 'sessions', GatewayConfig())
    telegram = TelegramAdapter(PlatformConfig()); telegram._session_store = routes
    source = SessionSource(platform=Platform.TELEGRAM, chat_id='42', user_id='42', chat_type='dm')
    entry = routes.get_or_create_session(source)
    fixture = seed_approved_fixture(home, workspace, session_id=entry.session_id,
                                   task_id='task-stage2', user_id=42, chat_id=42)
    session_context.set_session_vars(platform='telegram', chat_type='dm', chat_id='42', user_id='42',
                                     session_key=entry.session_key, session_id=entry.session_id, profile='default')
    approval_context._approval_session_id.set(entry.session_id)
    approval_context._approval_turn_id.set('turn-stage2')
    approval_context._approval_tool_call_id.set('call-stage2')

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ReviewerKeyRegistry(fixture.store).register_reviewer_key(
        ReviewerPublicKey('stage2-key', 'stage2-reviewer', 'test-provider', public))
    manager = get_plugin_manager()
    manager._load_plugin(PluginManifest(name='engineering-gate', version='0.1.0',
                                        path=os.environ['PLUGIN_PATH'], source='project'))
    loaded = manager._plugins['engineering-gate']; assert not loaded.error, loaded.error
    assert len(manager._tool_execution_interceptors) == 1
    interceptor = manager._tool_execution_interceptors[0][1]
    adapter = getattr(interceptor, '__self__', None)
    assert adapter is not None, 'registered interceptor is not bound to Gate adapter instance'
    assert hasattr(adapter, '_reviewer_verdict_provider'), 'Gate adapter lacks reviewer provider seam'

    signed_authorization = __import__(
        loaded.module.__name__ + '.engineering_gate_core.signed_authorization', fromlist=['*']
    )

    class OneShotReviewer:
        used = False
        def __call__(self, task_id, proposal):
            assert not self.used, 'review provider is one-shot'; self.used = True
            assert task_id == 'task-stage2'
            assert proposal.operation.kind.value == 'write' and proposal.operation.target == final_path
            assert proposal.argument_digest == mutation_argument_digest('approved bytes')
            state = fixture.store.load(task_id)
            payload = {'schema_version': 1, 'signature_algorithm': 'Ed25519', 'key_id': 'stage2-key',
                'review_id': 'stage2-review', 'reviewer_id': 'stage2-reviewer',
                'reviewer_provider': 'test-provider', 'implementer_id': 'engineering-gate-hermes',
                'task_id': task_id, 'plan_revision': int(state.revision), 'plan_digest': str(state.plan_digest),
                'proposal_digest': canonical_mutation_proposal_digest(proposal), 'verdict': 'approve',
                'reviewed_at': datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')}
            encoded = canonical_signed_verdict(payload)
            return signed_authorization.SignedMutationVerdict(
                encoded, private.sign(signed_authorization.DOMAIN_PREFIX + encoded))
    provider = OneShotReviewer()

    request_seen = []; execution_seen = []; intercepted = []
    def observe(name, args, **context):
        intercepted.append((name, dict(args), context)); return interceptor(name, args, **context)
    manager._tool_execution_interceptors[0] = (
        manager._tool_execution_interceptors[0][0], observe, manager._tool_execution_interceptors[0][2])
    def request_middleware(**p):
        request_seen.append(dict(p['args'])); return {'args': p['args']}
    def execution_middleware(**p):
        execution_seen.append(dict(p['args']))
        if p['tool_name'] == 'write_file':
            return p['next_call']({**p['args'], 'path': final_path})
        return p['next_call']()
    manager._middleware.setdefault('tool_request', []).append(request_middleware)
    manager._middleware.setdefault('tool_execution', []).append(execution_middleware)

    write_entry = registry.get_entry('write_file', scope=str(home)); assert write_entry
    native_calls = []; native_handler = write_entry.handler
    def forbidden(*args, **kwargs):
        native_calls.append((args, kwargs)); raise AssertionError('native write_file invoked')
    write_entry.handler = forbidden
    request = fixture.store.load('task-stage2').approval_request
    row = fixture.sidecar.find_unique_approved('default', 'task-stage2', request.request_id)
    assert row is not None
    return DispatchHarness(home, workspace, routes, entry, fixture, manager, adapter, provider,
        request_seen, execution_seen, intercepted, native_calls, write_entry, native_handler,
        None, row['nonce'], row['plan_display_digest'])
