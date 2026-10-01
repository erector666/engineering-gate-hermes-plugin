import sys
import tempfile
import threading
from contextlib import contextmanager
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.a3_execution import GateWriteService
from datetime import datetime, timezone
from dataclasses import replace
from engineering_gate_core.models import (ApprovalReceipt, ApprovalRequest, ExecutionPermit, MutationAuthorization, MutationProposal, MutationScope, NormalizedOperation, OperationKind, Plan, PlanReview, ReviewVerdict, Task, TaskState, TaskStateRecord, RequesterIdentity)
from engineering_gate_core.workflow import canonical_plan_digest, canonical_mutation_proposal_digest, mutation_argument_digest, record_mutation_authorization, record_mutation_proposal, capture_workspace_identity


class SyntheticAuthorizationProvider:
    """Test-only registry; it does not authenticate a human approver."""

    def __init__(self):
        self._approvals = set()
        self._lock = threading.Lock()

    def issue(self, authorization):
        with self._lock:
            self._approvals.add(authorization)

    def revoke(self, authorization_id):
        with self._lock:
            self._approvals = {approval for approval in self._approvals if approval.authorization_id != authorization_id}

    def verify(self, authorization, proposal):
        with self._lock:
            return (authorization in self._approvals and
                    authorization.proposal_digest == canonical_mutation_proposal_digest(proposal))

    @contextmanager
    def acquire_lease(self, authorization, proposal):
        self._lock.acquire()
        try:
            if not (authorization in self._approvals and authorization.proposal_digest == canonical_mutation_proposal_digest(proposal)):
                raise PermissionError("authorization revoked")
            yield
        finally:
            self._lock.release()


class GateOwnedWriteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.states = {}
        self.authorization_provider = SyntheticAuthorizationProvider()
        self.transaction_calls = 0
        def state_transaction(task_id, callback):
            self.transaction_calls += 1
            return callback(self.states[task_id])
        self.state_transaction = state_transaction
        self.service = GateWriteService(self.root, state_loader=self.states.__getitem__,
                                        state_transaction=state_transaction,
                                        authorization_verifier=self.authorization_provider.verify,
                                        authorization_lease_provider=self.authorization_provider.acquire_lease,
                                        clock=lambda: datetime(2026, 10, 1, 12, tzinfo=timezone.utc))
        self.addCleanup(self.service.close)

    def state_for(self, operation=None, state=TaskState.IMPLEMENTING, task_id="task-1", revision=1):
        operation = operation or NormalizedOperation(OperationKind.WRITE, "approved.txt")
        task = Task(task_id, "write file", RequesterIdentity("requester"))
        plan = Plan("write file", (operation,), (), (), workspace_root=str(self.root.resolve()),
                    workspace_identity=capture_workspace_identity(str(self.root.resolve())))
        digest = canonical_plan_digest(plan)
        approval = ApprovalReceipt("req-1", task_id, revision, digest, task.requester, True)
        permit = ExecutionPermit(task_id, revision, digest, MutationScope((operation,)))
        approval_request = ApprovalRequest(task_id, revision, digest, "req-1")
        record = TaskStateRecord(task, state, revision, (), plan=plan, plan_digest=digest,
                                 plan_review=PlanReview(ReviewVerdict.APPROVED), approval_request=approval_request,
                                 approval=approval, permit=permit)
        if state is TaskState.IMPLEMENTING and operation.kind is OperationKind.WRITE and "/" not in operation.target and "\\" not in operation.target and operation.target not in (".", ".."):
            content = "approved"
            proposal = MutationProposal("proposal-1", task_id, revision, digest, operation,
                                        mutation_argument_digest(content), "test-only reviewed proposal")
            record = record_mutation_proposal(record, proposal)
            authorization = MutationAuthorization("auth-1", task_id, revision, digest,
                canonical_mutation_proposal_digest(proposal), "synthetic-test-provider",
                "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z")
            self.authorization_provider.issue(authorization)
            record = record_mutation_authorization(record, authorization, now="2026-10-01T12:00:00Z")
        self.states[task_id] = record
        return record

    def state_for_other_task(self):
        return self.state_for(task_id="other-task")

    def state_for_revision_two(self):
        return self.state_for(revision=2)

    def test_permit_issue_requires_reviewed_proposal_and_provider_authorization(self):
        operation = NormalizedOperation(OperationKind.WRITE, "approved.txt")
        state = self.state_for(operation)
        self.states[state.task_id] = replace(state, mutation_proposal=None, mutation_authorization=None)
        with self.assertRaises(PermissionError):
            self.service.issue_permit(task_id=state.task_id, operation=operation,
                                      arguments={"content": "approved"})

    def test_authorization_expired_before_issue_is_denied(self):
        self.service._clock = lambda: datetime(2026, 10, 2, 0, tzinfo=timezone.utc)
        with self.assertRaises(PermissionError):
            self.permit()

    def test_verifier_false_nonboolean_and_exception_all_deny(self):
        original = self.service._authorization_verifier
        for verifier in (lambda auth, proposal: False, lambda auth, proposal: "yes",
                         lambda auth, proposal: (_ for _ in ()).throw(RuntimeError("provider down")), None):
            with self.subTest(verifier=verifier):
                self.service._authorization_verifier = verifier
                with self.assertRaises(PermissionError):
                    self.permit()
        self.service._authorization_verifier = original

    def test_provider_rejects_forged_authority_id(self):
        state = self.state_for()
        authorization = state.mutation_authorization
        forged = replace(authorization, authority_id="attacker")
        self.assertFalse(self.authorization_provider.verify(forged, state.mutation_proposal))

    def test_forged_authority_before_permit_issue_is_denied(self):
        state = self.state_for()
        forged = replace(state.mutation_authorization, authority_id="attacker")
        self.states[state.task_id] = replace(state, mutation_authorization=forged)
        with self.assertRaises(PermissionError):
            self.permit(state=self.states[state.task_id])

    def test_provider_rejects_forged_expiry_on_registered_authorization(self):
        state = self.state_for()
        authorization = state.mutation_authorization
        forged = replace(authorization, expires_at="2026-10-03T00:00:00Z")
        self.assertFalse(self.authorization_provider.verify(forged, state.mutation_proposal))

    def test_forged_authorization_id_is_denied(self):
        permit = self.permit()
        state = self.states["task-1"]
        self.states["task-1"] = replace(
            state, mutation_authorization=replace(state.mutation_authorization, authorization_id="forged-auth-id"))
        with self.assertRaises(PermissionError):
            self.request(permit)
        self.assertFalse((self.root / "approved.txt").exists())

    def test_provider_revocation_after_permit_issue_denies_execution(self):
        permit = self.permit()
        self.authorization_provider.revoke("auth-1")
        with self.assertRaises(PermissionError):
            self.request(permit)
        self.assertFalse((self.root / "approved.txt").exists())

    def test_authorization_expiring_after_issue_denies_execution(self):
        permit = self.permit()
        self.service._clock = lambda: datetime(2026, 10, 2, 0, tzinfo=timezone.utc)
        with self.assertRaises(PermissionError):
            self.request(permit)
        self.assertFalse((self.root / "approved.txt").exists())

    def test_proposal_replacement_after_issue_invalidates_permit(self):
        permit = self.permit()
        state = self.states["task-1"]
        replacement = MutationProposal("proposal-replaced", state.task_id, state.revision,
            state.plan_digest, NormalizedOperation(OperationKind.WRITE, "approved.txt"),
            mutation_argument_digest("approved"), "replacement reviewed proposal")
        self.states["task-1"] = record_mutation_proposal(state, replacement)
        with self.assertRaises(PermissionError):
            self.request(permit)

    def test_staging_filename_collision_never_writes_directly_to_target(self):
        import os
        from unittest.mock import patch

        collision = ".gate-write-" + "a" * 32 + ".tmp"
        operation = NormalizedOperation(OperationKind.WRITE, collision)
        permit = self.permit(operation=operation)
        real_write = os.write
        target_existed_during_write = []

        def assert_target_absent_during_staging(fd, data):
            target_existed_during_write.append((self.root / collision).exists())
            return real_write(fd, data)

        with patch("engineering_gate_core.a3_execution.secrets.token_hex", side_effect=["a" * 32, "b" * 32]):
            with patch("engineering_gate_core.a3_execution.os.write", side_effect=assert_target_absent_during_staging):
                result = self.request(permit, operation=operation)

        self.assertEqual(target_existed_during_write, [False])
        self.assertEqual(result.read_text(), "approved")

    def test_root_path_replacement_is_denied_before_write(self):
        moved = self.root.with_name(self.root.name + "-moved")
        replacement = Path(tempfile.mkdtemp(dir=self.root.parent))
        self.addCleanup(lambda: replacement.exists() and __import__('shutil').rmtree(replacement))
        self.root.rename(moved)
        replacement.rename(self.root)
        permit = self.permit()
        with self.assertRaises(PermissionError):
            self.request(permit)
        self.assertFalse((moved / "approved.txt").exists())
        self.assertFalse((self.root / "approved.txt").exists())

    def test_moved_root_without_replacement_is_denied(self):
        moved = self.root.with_name(self.root.name + "-moved")
        permit = self.permit()
        self.root.rename(moved)
        with self.assertRaises(PermissionError):
            self.request(permit)
        self.assertFalse((moved / "approved.txt").exists())

    def test_root_path_replaced_by_symlink_is_denied(self):
        moved = self.root.with_name(self.root.name + "-moved")
        permit = self.permit()
        self.root.rename(moved)
        self.root.symlink_to(moved, target_is_directory=True)
        self.addCleanup(self.root.unlink, missing_ok=True)
        self.addCleanup(lambda: __import__('shutil').rmtree(moved, ignore_errors=True))
        with self.assertRaises(PermissionError):
            self.request(permit)
        self.assertFalse((moved / "approved.txt").exists())

    def test_child_additions_and_deletions_do_not_change_root_identity(self):
        (self.root / "added").touch()
        (self.root / "removed").touch()
        (self.root / "removed").unlink()
        result = self.request(self.permit())
        self.assertEqual(result.read_text(), "approved")

    def test_root_rename_after_temp_staging_denies_before_replace(self):
        import os
        from unittest.mock import patch
        moved = self.root.with_name(self.root.name + "-moved")
        permit = self.permit()
        real_write = os.write
        renamed = False

        def write_then_rename(fd, data):
            nonlocal renamed
            result = real_write(fd, data)
            if not renamed:
                self.root.rename(moved)
                renamed = True
            return result

        with patch("engineering_gate_core.a3_execution.os.write", side_effect=write_then_rename):
            with self.assertRaises(PermissionError):
                self.request(permit)
        self.assertFalse((moved / "approved.txt").exists())

    def test_moved_nested_parent_cannot_escape_because_nested_writes_are_unsupported(self):
        nested = self.root / "nested"
        nested.mkdir()
        outside = self.root.parent / (self.root.name + "-outside")
        try:
            with self.assertRaises(PermissionError):
                self.permit(target="nested/file.txt")
            self.assertFalse((outside / "file.txt").exists())
            self.assertFalse((nested / "file.txt").exists())
        finally:
            if outside.exists():
                outside.rename(nested)

    def test_root_swap_between_identity_validation_and_replace_reports_detached_write(self):
        import os
        from unittest.mock import patch
        from engineering_gate_core.a3_execution import WorkspacePathDetached

        moved = self.root.with_name(self.root.name + "-moved-before-replace")
        replacement = Path(tempfile.mkdtemp(dir=self.root.parent))
        permit = self.permit()
        real_replace = os.replace
        swapped = False

        def swap_root_then_replace(*args, **kwargs):
            nonlocal swapped
            if not swapped:
                self.root.rename(moved)
                replacement.rename(self.root)
                swapped = True
            return real_replace(*args, **kwargs)

        try:
            with patch("engineering_gate_core.a3_execution.os.replace", side_effect=swap_root_then_replace):
                with self.assertRaisesRegex(WorkspacePathDetached, "write completed.*approved workspace path changed"):
                    self.request(permit)
            self.assertEqual((moved / "approved.txt").read_text(), "approved")
            self.assertFalse((self.root / "approved.txt").exists())
        finally:
            if self.root.exists():
                import shutil
                shutil.rmtree(self.root)
            if moved.exists():
                moved.rename(self.root)
            if replacement.exists():
                import shutil
                shutil.rmtree(replacement)

    def test_detached_write_error_surfaces_after_transaction_callback_completes(self):
        import os
        from unittest.mock import patch
        from engineering_gate_core.a3_execution import WorkspacePathDetached

        moved = self.root.with_name(self.root.name + "-moved-after-replace")
        replacement = Path(tempfile.mkdtemp(dir=self.root.parent))
        permit = self.permit()
        real_replace = os.replace
        transaction_finished = []

        def swap_root_then_replace(*args, **kwargs):
            self.root.rename(moved)
            replacement.rename(self.root)
            return real_replace(*args, **kwargs)

        def recording_transaction(task_id, callback):
            outcome = callback(self.states[task_id])
            transaction_finished.append(outcome)
            return outcome

        self.service._state_transaction = recording_transaction
        try:
            with patch("engineering_gate_core.a3_execution.os.replace", side_effect=swap_root_then_replace):
                with self.assertRaises(WorkspacePathDetached):
                    self.request(permit)
            self.assertEqual(len(transaction_finished), 1)
            self.assertTrue(transaction_finished[0].path_detached)
            self.assertTrue(transaction_finished[0].audit_record.path_detached)
            self.assertEqual((moved / "approved.txt").read_text(), "approved")
            self.assertFalse((self.root / "approved.txt").exists())
        finally:
            if self.root.exists():
                import shutil
                shutil.rmtree(self.root)
            if moved.exists():
                moved.rename(self.root)
            if replacement.exists():
                import shutil
                shutil.rmtree(replacement)

    def test_root_swap_after_transaction_callback_does_not_return_stale_path(self):
        from engineering_gate_core.a3_execution import WorkspacePathDetached

        moved = self.root.with_name(self.root.name + "-moved-before-return")
        replacement = Path(tempfile.mkdtemp(dir=self.root.parent))
        permit = self.permit()

        def swap_after_callback(task_id, callback):
            outcome = callback(self.states[task_id])
            self.root.rename(moved)
            replacement.rename(self.root)
            return outcome

        self.service._state_transaction = swap_after_callback
        try:
            with self.assertRaises(WorkspacePathDetached):
                self.request(permit)
            self.assertEqual((moved / "approved.txt").read_text(), "approved")
            self.assertFalse((self.root / "approved.txt").exists())
        finally:
            if self.root.exists():
                import shutil
                shutil.rmtree(self.root)
            if moved.exists():
                moved.rename(self.root)
            if replacement.exists():
                import shutil
                shutil.rmtree(replacement)

    def test_nested_target_write_is_rejected_before_permit(self):
        operation = NormalizedOperation(OperationKind.WRITE, "nested/file.txt")
        state = self.state_for(operation)
        with self.assertRaises(PermissionError):
            self.service.issue_permit(task_id=state.task_id, operation=operation,
                                      arguments={"content": "approved"})

    def test_non_implementing_state_cannot_mint_a_write_permit(self):
        operation = NormalizedOperation(OperationKind.WRITE, "approved.txt")
        state = self.state_for(operation, TaskState.APPROVED)
        with self.assertRaises(PermissionError):
            self.service.issue_permit(task_id=state.task_id, operation=operation,
                                      arguments={"content": "approved"})

    def test_state_change_after_permit_mint_blocks_execution(self):
        from dataclasses import replace
        operation = NormalizedOperation(OperationKind.WRITE, "approved.txt")
        original = self.state_for(operation)
        permit = self.permit(operation=operation, state=original)
        self.states["task-1"] = replace(original, state=TaskState.CANCELLED)
        with self.assertRaises(PermissionError):
            self.request(permit, operation=operation)
        self.assertFalse((self.root / "approved.txt").exists())

    def test_execute_validates_fresh_state_supplied_by_transaction(self):
        from dataclasses import replace
        operation = NormalizedOperation(OperationKind.WRITE, "approved.txt")
        initial = self.state_for(operation)
        permit = self.permit(operation=operation, state=initial)
        self.states["task-1"] = replace(initial, state=TaskState.CANCELLED)
        with self.assertRaises(PermissionError):
            self.service.execute(permit, task_id="task-1", operation=operation,
                                 arguments={"content": "approved"})
        self.assertFalse((self.root / "approved.txt").exists())

    def test_missing_transaction_support_fails_closed(self):
        with self.assertRaises(TypeError):
            GateWriteService(self.root, state_loader=self.states.__getitem__)

    def test_state_transaction_encloses_filesystem_write(self):
        operation = NormalizedOperation(OperationKind.WRITE, "approved.txt")
        permit = self.permit(operation=operation)
        inside = threading.Event()
        released = threading.Event()
        original_transaction = self.state_transaction
        def blocking_transaction(task_id, callback):
            def guarded(state):
                inside.set()
                if not released.wait(2):
                    raise AssertionError("test did not release transaction")
                return callback(state)
            return original_transaction(task_id, guarded)
        self.service._state_transaction = blocking_transaction
        result = []
        worker = threading.Thread(target=lambda: result.append(self.request(permit)))
        worker.start()
        self.assertTrue(inside.wait(2))
        self.assertFalse((self.root / "approved.txt").exists())
        released.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [self.root / "approved.txt"])

    def test_pre_mutation_provider_revocation_retains_permit_for_retry(self):
        import os
        from unittest.mock import patch
        permit = self.permit()
        real_write = os.write
        revoked = False
        def write_then_revoke(fd, data):
            nonlocal revoked
            result = real_write(fd, data)
            if not revoked:
                revoked = True
                self.authorization_provider.revoke("auth-1")
            return result
        with patch("engineering_gate_core.a3_execution.os.write", side_effect=write_then_revoke):
            with self.assertRaises(PermissionError):
                self.request(permit)
        self.assertFalse((self.root / "approved.txt").exists())
        state = self.states["task-1"]
        self.authorization_provider.issue(state.mutation_authorization)
        self.assertEqual(self.request(permit).read_text(), "approved")

    def test_revocation_waits_for_held_authorization_lease_through_replace(self):
        import os
        from unittest.mock import patch
        permit = self.permit()
        real_replace = os.replace
        revoke_started, replaced = threading.Event(), threading.Event()
        revoker = None
        def replace_while_revocation_waits(*args, **kwargs):
            nonlocal revoker
            def revoke():
                revoke_started.set()
                self.authorization_provider.revoke("auth-1")
            revoker = threading.Thread(target=revoke)
            revoker.start()
            self.assertTrue(revoke_started.wait(2))
            result = real_replace(*args, **kwargs)
            replaced.set()
            return result
        with patch("engineering_gate_core.a3_execution.os.replace", side_effect=replace_while_revocation_waits):
            result = self.request(permit)
        revoker.join(2)
        self.assertFalse(revoker.is_alive())
        self.assertTrue(replaced.is_set())
        self.assertEqual(result.read_text(), "approved")

    def test_missing_lease_provider_fails_closed_and_retains_permit(self):
        permit = self.permit()
        provider = self.service._authorization_lease_provider
        self.service._authorization_lease_provider = None
        with self.assertRaises(PermissionError):
            self.request(permit)
        self.assertFalse((self.root / "approved.txt").exists())
        self.service._authorization_lease_provider = provider
        self.assertEqual(self.request(permit).read_text(), "approved")

    def test_lease_acquisition_rejection_retains_permit_for_retry(self):
        permit = self.permit()
        provider = self.authorization_provider
        reject = True
        def acquire(auth, proposal):
            if reject:
                raise PermissionError("reservation unavailable")
            return provider.acquire_lease(auth, proposal)
        self.service._authorization_lease_provider = acquire
        with self.assertRaises(PermissionError):
            self.request(permit)
        self.assertFalse((self.root / "approved.txt").exists())
        reject = False
        self.assertEqual(self.request(permit).read_text(), "approved")

    def test_pre_mutation_clock_rejection_retains_permit_for_retry(self):
        permit = self.permit()
        original_clock = self.service._clock
        self.service._clock = lambda: (_ for _ in ()).throw(RuntimeError("clock unavailable"))
        with self.assertRaises(RuntimeError):
            self.request(permit)
        self.assertFalse((self.root / "approved.txt").exists())
        self.service._clock = original_clock
        self.assertEqual(self.request(permit).read_text(), "approved")

    def test_concurrent_execution_reserves_permit_once(self):
        from unittest.mock import patch
        permit = self.permit()
        entered = threading.Event()
        release = threading.Event()
        outcomes = []
        real_write = __import__("os").write
        def paused_write(fd, data):
            entered.set()
            if not release.wait(2):
                raise AssertionError("test did not release filesystem write")
            return real_write(fd, data)
        def execute():
            try:
                outcomes.append(self.request(permit))
            except Exception as exc:
                outcomes.append(exc)
        with patch("engineering_gate_core.a3_execution.os.write", side_effect=paused_write):
            first = threading.Thread(target=execute)
            first.start()
            self.assertTrue(entered.wait(2))
            second = threading.Thread(target=execute)
            second.start()
            second.join(2)
            self.assertFalse(second.is_alive())
            release.set()
            first.join(2)
        self.assertFalse(first.is_alive())
        self.assertEqual(sum(isinstance(item, Path) for item in outcomes), 1)
        self.assertEqual(sum(isinstance(item, PermissionError) for item in outcomes), 1)

    def permit(self, **overrides):
        operation = overrides.pop("operation", NormalizedOperation(OperationKind.WRITE, overrides.pop("target", "approved.txt")))
        state = overrides.pop("state", self.state_for(operation))
        arguments = overrides.pop("arguments", {"content": "approved"})
        if overrides:
            raise TypeError(overrides)
        self.states[str(state.task_id)] = state
        return self.service.issue_permit(task_id=state.task_id, operation=operation, arguments=arguments)

    def request(self, permit, **overrides):
        operation = overrides.pop("operation", NormalizedOperation(OperationKind.WRITE, overrides.pop("target", "approved.txt")))
        state = overrides.pop("state", self.states.get("task-1") or self.state_for(operation))
        arguments = overrides.pop("arguments", {"content": "approved"})
        if overrides:
            raise TypeError(overrides)
        return self.service.execute(permit, task_id=state.task_id, operation=operation, arguments=arguments)

    def test_lease_exit_failure_after_replace_consumes_permit(self):
        from engineering_gate_core.a3_execution import MutationOutcomeUnknown

        permit = self.permit()
        provider = self.authorization_provider

        class ExitFailureLease:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                raise RuntimeError("simulated lease release failure")

        self.service._authorization_lease_provider = lambda auth, proposal: ExitFailureLease()

        with self.assertRaises(MutationOutcomeUnknown):
            self.request(permit)

        self.assertEqual((self.root / "approved.txt").read_text(), "approved")
        self.service._authorization_lease_provider = provider.acquire_lease
        with self.assertRaises(PermissionError):
            self.request(permit)

    def test_transaction_failure_after_write_reports_unknown_outcome(self):
        operation = NormalizedOperation(OperationKind.WRITE, "approved.txt")
        permit = self.permit(operation=operation)

        def failing_transaction(task_id, callback):
            callback(self.states[task_id])
            raise OSError("simulated SQLite commit failure")

        self.service._state_transaction = failing_transaction
        with self.assertRaises(Exception) as raised:
            self.service.execute(permit, task_id="task-1", operation=operation,
                                 arguments={"content": "approved"})

        self.assertEqual(type(raised.exception).__name__, "MutationOutcomeUnknown")
        self.assertTrue((self.root / "approved.txt").exists())

    def test_audit_digest_comes_from_readback_bytes_after_replace(self):
        import hashlib
        import os
        from unittest.mock import patch
        from engineering_gate_core.a3_execution import MutationOutcomeUnknown

        permit = self.permit()
        real_replace = os.replace
        real_write = os.write
        def replace_then_modify(*args, **kwargs):
            result = real_replace(*args, **kwargs)
            target_fd = os.open("approved.txt", os.O_WRONLY, dir_fd=kwargs["dst_dir_fd"])
            try:
                os.ftruncate(target_fd, 0)
                real_write(target_fd, b"observed bytes")
            finally:
                os.close(target_fd)
            return result
        audits = []
        def transaction(task_id, callback):
            outcome = callback(self.states[task_id])
            audits.append(outcome.audit_record)
            return outcome
        self.service._state_transaction = transaction
        with patch("engineering_gate_core.a3_execution.os.replace", side_effect=replace_then_modify):
            self.request(permit)
        self.assertEqual((self.root / "approved.txt").read_bytes(), b"observed bytes")
        self.assertEqual(audits[0].resulting_artifact_digest, hashlib.sha256(b"observed bytes").hexdigest())

    def test_replaced_readback_target_records_unknown_outcome(self):
        import os
        from unittest.mock import patch
        from engineering_gate_core.a3_execution import MutationOutcomeUnknown
        permit = self.permit()
        real_read = os.read
        swapped = False
        def read_then_swap(fd, size):
            nonlocal swapped
            if not swapped:
                target = self.root / "approved.txt"
                target.rename(self.root / "displaced.txt")
                target.write_bytes(b"replacement")
                swapped = True
            return real_read(fd, size)
        audits = []
        def transaction(task_id, callback):
            result = callback(self.states[task_id])
            audits.append(result.audit_record)
            return result
        self.service._state_transaction = transaction
        with patch("engineering_gate_core.a3_execution.os.read", side_effect=read_then_swap):
            with self.assertRaises(MutationOutcomeUnknown):
                self.request(permit)
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0].outcome.value, "outcome_unknown")
        self.assertIsNone(audits[0].resulting_artifact_digest)
        self.assertEqual(audits[0].error_class, "OSError")

    def test_valid_permit_writes_only_its_authorized_file(self):
        permit = self.permit()
        result = self.request(permit)
        self.assertEqual(result, self.root / "approved.txt")
        self.assertEqual(result.read_text(), "approved")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["approved.txt"])

    def test_argument_digest_mismatch_is_rejected(self):
        permit = self.permit()
        with self.assertRaises(PermissionError):
            self.request(permit, arguments={"content": "tampered"})

    def test_target_mismatch_is_rejected(self):
        permit = self.permit()
        with self.assertRaises(PermissionError):
            self.request(permit, target="other.txt")

    def test_task_mismatch_does_not_consume_valid_permit(self):
        permit = self.permit()
        with self.assertRaises(PermissionError):
            self.request(permit, state=self.state_for_other_task())
        self.assertEqual(self.request(permit).read_text(), "approved")

    def test_in_place_mutation_during_readback_records_unknown_outcome(self):
        import os
        from unittest.mock import patch
        from engineering_gate_core.a3_execution import MutationOutcomeUnknown

        permit = self.permit()
        real_read = os.read
        mutated = False
        audits = []

        def read_then_mutate(fd, size):
            nonlocal mutated
            data = real_read(fd, size)
            if not mutated and data:
                mutated = True
                target_fd = os.open(self.root / "approved.txt", os.O_WRONLY)
                try:
                    os.pwrite(target_fd, b"!", 0)
                finally:
                    os.close(target_fd)
            return data

        def transaction(task_id, callback):
            result = callback(self.states[task_id])
            audits.append(result.audit_record)
            return result

        self.service._state_transaction = transaction
        with patch("engineering_gate_core.a3_execution.os.read", side_effect=read_then_mutate):
            with self.assertRaises(MutationOutcomeUnknown):
                self.request(permit)
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0].outcome.value, "outcome_unknown")
        self.assertIsNone(audits[0].resulting_artifact_digest)
        self.assertEqual(audits[0].error_class, "OSError")

    def test_plan_revision_mismatch_is_rejected(self):
        permit = self.permit()
        self.states["task-1"] = self.state_for_revision_two()
        with self.assertRaises(PermissionError):
            self.request(permit)

    def test_caller_snapshot_cannot_override_transaction_state(self):
        permit = self.permit()
        current = self.states["task-1"]
        caller_snapshot = self.state_for_revision_two()
        self.states["task-1"] = current
        result = self.request(permit, state=caller_snapshot)
        self.assertEqual(result.read_text(), "approved")

    def test_operation_mismatch_is_rejected(self):
        permit = self.permit()
        with self.assertRaises(PermissionError):
            self.request(permit, operation=NormalizedOperation(OperationKind.DELETE, "approved.txt"))

    def test_permit_replay_is_rejected(self):
        permit = self.permit()
        self.request(permit)
        with self.assertRaises(PermissionError):
            self.request(permit)

    def test_unknown_operation_cannot_be_permitted(self):
        with self.assertRaises(PermissionError):
            self.permit(operation=NormalizedOperation(OperationKind.UNKNOWN, "approved.txt"))

    def test_write_does_not_follow_hard_link_outside_workspace(self):
        with tempfile.TemporaryDirectory() as outside_dir:
            outside = Path(outside_dir) / "outside.txt"
            outside.write_text("external original")
            linked = self.root / "approved.txt"
            linked.hardlink_to(outside)
            permit = self.permit()

            self.request(permit)

            self.assertEqual(outside.read_text(), "external original")
            self.assertEqual(linked.read_text(), "approved")

    def test_final_symlink_is_rejected_without_modifying_target(self):
        with tempfile.TemporaryDirectory() as outside_dir:
            outside = Path(outside_dir) / "outside.txt"
            outside.write_text("external original")
            (self.root / "approved.txt").symlink_to(outside)
            with self.assertRaises(PermissionError):
                self.permit()

            self.assertEqual(outside.read_text(), "external original")

    def test_intermediate_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as outside_dir:
            (self.root / "linked-dir").symlink_to(outside_dir, target_is_directory=True)
            with self.assertRaises(PermissionError):
                self.permit(target="linked-dir/file.txt")
            self.assertFalse((Path(outside_dir) / "file.txt").exists())

    def test_failed_atomic_write_preserves_existing_file(self):
        import unittest.mock
        target = self.root / "approved.txt"
        target.write_text("original")
        permit = self.permit()
        with unittest.mock.patch("engineering_gate_core.a3_execution.os.write", side_effect=OSError("disk failure")):
            with self.assertRaises(OSError):
                self.request(permit)
        self.assertEqual(target.read_text(), "original")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["approved.txt"])

    def test_parent_traversal_is_rejected(self):
        outside = self.root.parent / "outside.txt"
        before = outside.read_bytes() if outside.exists() else None
        with self.assertRaises(PermissionError):
            self.permit(target="../outside.txt")
        self.assertEqual(outside.read_bytes() if outside.exists() else None, before)

    def test_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            (self.root / "escape").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(PermissionError):
                self.permit(target="escape/file.txt")
            self.assertFalse((Path(outside) / "file.txt").exists())


if __name__ == "__main__":
    unittest.main()
