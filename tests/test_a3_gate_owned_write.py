import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.a3_execution import GateWriteService
from engineering_gate_core.models import (ApprovalReceipt, ExecutionPermit, MutationScope, NormalizedOperation, OperationKind, Plan, Task, TaskState, TaskStateRecord, RequesterIdentity)
from engineering_gate_core.workflow import canonical_plan_digest, capture_workspace_identity


class GateOwnedWriteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.states = {}
        self.transaction_calls = 0
        def state_transaction(task_id, callback):
            self.transaction_calls += 1
            return callback(self.states[task_id])
        self.state_transaction = state_transaction
        self.service = GateWriteService(self.root, state_loader=self.states.__getitem__,
                                        state_transaction=state_transaction)

    def state_for(self, operation=None, state=TaskState.IMPLEMENTING, task_id="task-1", revision=1):
        operation = operation or NormalizedOperation(OperationKind.WRITE, "approved.txt")
        task = Task(task_id, "write file", RequesterIdentity("requester"))
        plan = Plan("write file", (operation,), (), (), workspace_root=str(self.root.resolve()),
                    workspace_identity=capture_workspace_identity(str(self.root.resolve())))
        digest = canonical_plan_digest(plan)
        approval = ApprovalReceipt("req-1", task_id, revision, digest, task.requester, True)
        permit = ExecutionPermit(task_id, revision, digest, MutationScope((operation,)))
        record = TaskStateRecord(task, state, revision, (), plan=plan, plan_digest=digest,
                                 approval=approval, permit=permit)
        self.states[task_id] = record
        return record

    def state_for_other_task(self):
        return self.state_for(task_id="other-task")

    def state_for_revision_two(self):
        return self.state_for(revision=2)

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
            self.assertFalse(isinstance(transaction_finished[0], Exception))
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

    def test_task_mismatch_is_rejected(self):
        permit = self.permit()
        with self.assertRaises(PermissionError):
            self.request(permit, state=self.state_for_other_task())

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
