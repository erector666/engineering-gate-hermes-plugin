import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.models import RequesterIdentity, TaskStateRecord, TaskState
from engineering_gate_core.workflow import new_task


class StateStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.record = new_task("task-1", "inspect project", RequesterIdentity("user-1"))

    def test_create_rejects_fabricated_advanced_state(self):
        from dataclasses import replace
        from engineering_gate_core.state_store import StateStore, StateStoreError
        from engineering_gate_core.models import ApprovalReceipt, ExecutionPermit, MutationScope, PlanDigest, PlanRevision

        fabricated = replace(
            self.record,
            state=TaskState.IMPLEMENTING,
            revision=PlanRevision(1),
            history=(TaskState.INTAKE, TaskState.INSPECT, TaskState.ANALYZE, TaskState.PLAN,
                     TaskState.BLAST_RADIUS, TaskState.PLAN_REVIEW, TaskState.AWAITING_APPROVAL,
                     TaskState.APPROVED, TaskState.IMPLEMENTING),
            approval=ApprovalReceipt("approval-1", self.record.task_id, PlanRevision(1),
                                     PlanDigest("fabricated"), self.record.task.requester, True),
            permit=ExecutionPermit(self.record.task_id, PlanRevision(1), PlanDigest("fabricated"),
                                   MutationScope(())),
        )
        store = StateStore(self.path)
        with self.assertRaises(StateStoreError):
            store.create(fabricated)
        with self.assertRaises(StateStoreError):
            store.load(self.record.task_id)

    def test_reopen_retains_state(self):
        from engineering_gate_core.state_store import StateStore

        StateStore(self.path).create(self.record)
        self.assertEqual(StateStore(self.path).load("task-1"), self.record)

    def test_valid_event_is_applied_and_persisted(self):
        from engineering_gate_core.state_store import StateStore
        from engineering_gate_core.workflow import Event
        from engineering_gate_core.models import InspectionEvidenceRef

        store = StateStore(self.path)
        store.create(self.record)
        updated = store.transition("task-1", Event.INSPECTION_RECORDED,
                                   InspectionEvidenceRef("e-1", "source inspected"))
        self.assertEqual(updated.state, TaskState.ANALYZE)
        self.assertEqual(store.load("task-1"), updated)

    def test_illegal_transition_rolls_back_without_changing_record(self):
        from engineering_gate_core.state_store import StateStore
        from engineering_gate_core.workflow import Event, TransitionError

        store = StateStore(self.path)
        store.create(self.record)
        before = store.load("task-1")
        with self.assertRaises(TransitionError):
            store.transition("task-1", Event.PLAN_RECORDED, None)
        self.assertEqual(store.load("task-1"), before)

    def test_duplicate_create_is_rejected(self):
        from engineering_gate_core.state_store import StateStore, StateStoreError

        store = StateStore(self.path)
        store.create(self.record)
        with self.assertRaises(StateStoreError):
            store.create(self.record)

    def test_database_paths_are_isolated(self):
        from engineering_gate_core.state_store import StateStore, StateStoreError

        other = StateStore(Path(self.temp.name) / "other.sqlite3")
        StateStore(self.path).create(self.record)
        with self.assertRaises(StateStoreError):
            other.load("task-1")

    def test_transition_rejects_payload_with_wrong_task_key(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError
        from engineering_gate_core.workflow import Event

        store = StateStore(self.path)
        store.create(self.record)
        with sqlite3.connect(self.path) as db:
            (payload,) = db.execute(
                "SELECT payload FROM task_state WHERE task_id=?", ("task-1",)
            ).fetchone()
            db.execute(
                "UPDATE task_state SET task_id=? WHERE task_id=?", ("other-task", "task-1")
            )
        with self.assertRaises(StateStoreError):
            store.transition("other-task", Event.CANCEL)
        with sqlite3.connect(self.path) as db:
            (after,) = db.execute(
                "SELECT payload FROM task_state WHERE task_id=?", ("other-task",)
            ).fetchone()
        self.assertEqual(after, payload)

    def test_corrupt_json_fails_closed(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        store = StateStore(self.path)
        store.create(self.record)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE task_state SET payload='{' WHERE task_id='task-1'")
        with self.assertRaises(StateStoreError):
            store.load("task-1")

    def test_unsupported_schema_fails_closed(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        store = StateStore(self.path)
        store.create(self.record)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE metadata SET value='999' WHERE key='schema_version'")
        with self.assertRaises(StateStoreError):
            store.load("task-1")

    def test_database_file_is_private(self):
        import os
        import stat
        from engineering_gate_core.state_store import StateStore

        StateStore(self.path).create(self.record)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    @unittest.skipUnless(__import__("os").name == "posix", "POSIX permissions only")
    def test_database_path_setup_does_not_chmod_existing_file(self):
        from unittest.mock import patch
        from engineering_gate_core.state_store import StateStore

        import os
        self.path.touch()
        os.chmod(self.path, 0o600)
        with patch("engineering_gate_core.state_store.os.chmod", side_effect=AssertionError("chmod must not reopen the path")):
            StateStore(self.path)

    @unittest.skipUnless(__import__("os").name == "posix", "POSIX permissions only")
    def test_nested_created_parent_directories_are_private(self):
        import os
        import stat
        from engineering_gate_core.state_store import StateStore

        nested = Path(self.temp.name) / "private" / "nested" / "state.sqlite3"
        StateStore(nested).create(self.record)
        for directory in (nested.parent.parent, nested.parent):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    @unittest.skipUnless(__import__("os").name == "posix", "POSIX permissions only")
    def test_existing_parent_directory_mode_is_unchanged(self):
        import os
        import stat
        from engineering_gate_core.state_store import StateStore

        parent = Path(self.temp.name) / "existing"
        parent.mkdir(mode=0o755)
        os.chmod(parent, 0o755)
        StateStore(parent / "state.sqlite3").create(self.record)
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)

    @unittest.skipUnless(__import__("os").name == "posix", "POSIX symlinks only")
    def test_symlink_database_path_is_rejected(self):
        from engineering_gate_core.state_store import StateStore

        target = Path(self.temp.name) / "target.sqlite3"
        target.touch()
        self.path.symlink_to(target)
        with self.assertRaises(Exception):
            StateStore(self.path).create(self.record)
        self.assertEqual(target.stat().st_size, 0)

    def test_concurrent_terminal_transitions_only_one_applies(self):
        import threading
        from engineering_gate_core.state_store import StateStore
        from engineering_gate_core.workflow import Event, TransitionError

        store = StateStore(self.path)
        store.create(self.record)
        barrier = threading.Barrier(2)
        outcomes = []

        def cancel():
            barrier.wait()
            try:
                store.transition("task-1", Event.CANCEL)
                outcomes.append("applied")
            except TransitionError:
                outcomes.append("rejected")

        threads = [threading.Thread(target=cancel) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertCountEqual(outcomes, ["applied", "rejected"])
        self.assertEqual(store.load("task-1").state, TaskState.CANCELLED)

    def test_malformed_enum_fails_closed(self):
        import json
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        store = StateStore(self.path)
        store.create(self.record)
        with sqlite3.connect(self.path) as db:
            (payload,) = db.execute("SELECT payload FROM task_state WHERE task_id='task-1'").fetchone()
            value = json.loads(payload)
            value["state"]["value"] = "not-a-state"
            db.execute("UPDATE task_state SET payload=? WHERE task_id='task-1'", (json.dumps(value),))
        with self.assertRaises(StateStoreError):
            store.load("task-1")

    def test_create_and_load_round_trips_typed_state(self):
        from engineering_gate_core.state_store import StateStore

        store = StateStore(self.path)
        store.create(self.record)
        loaded = store.load("task-1")
        self.assertEqual(loaded, self.record)
        self.assertIsInstance(loaded, TaskStateRecord)
        self.assertIs(loaded.state, TaskState.INSPECT)
        self.assertEqual(loaded.task.requester, RequesterIdentity("user-1"))

    def test_mutation_records_persist_and_round_trip_typed(self):
        import sqlite3
        from dataclasses import replace
        from engineering_gate_core.state_store import StateStore, _record_json
        from engineering_gate_core.models import (AcceptanceCriterion, ApprovalReceipt, ExecutionPermit,
            MutationAuthorization, MutationProposal, MutationScope, NormalizedOperation, OperationKind,
            ApprovalRequest, Plan, PlanDigest, PlanReview, PlanRevision, ReviewVerdict)
        from engineering_gate_core.workflow import (canonical_mutation_proposal_digest, canonical_plan_digest,
            mutation_argument_digest)
        base = self.record
        from dataclasses import replace
        import tempfile
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "update output")
        root = str(Path(self.temp.name).resolve())
        plan = Plan("inspect project", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",),
                    workspace_root=root, workspace_identity=__import__("engineering_gate_core.workflow", fromlist=["capture_workspace_identity"]).capture_workspace_identity(root))
        digest = canonical_plan_digest(plan)
        current = replace(base, state=TaskState.IMPLEMENTING, revision=PlanRevision(1), plan=plan,
            plan_digest=digest, plan_review=PlanReview(ReviewVerdict.APPROVED),
            approval_request=ApprovalRequest(base.task_id, PlanRevision(1), digest, "r"),
            approval=ApprovalReceipt("r", base.task_id, PlanRevision(1), digest, base.task.requester, True),
            permit=ExecutionPermit(base.task_id, PlanRevision(1), digest, MutationScope((op,))))
        store = StateStore(self.path)
        store.create(base)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE task_state SET payload=? WHERE task_id=?", (_record_json(current), str(base.task_id)))
        proposal = MutationProposal("p", base.task_id, PlanRevision(1), digest, op,
                                    mutation_argument_digest("hello"), "reviewed write")
        recorded = store.record_mutation_proposal(base.task_id, proposal)
        auth = MutationAuthorization("a", base.task_id, PlanRevision(1), digest,
            canonical_mutation_proposal_digest(proposal), "provider", "2026-10-01T10:00:00Z", "2026-10-01T11:00:00Z")
        result = store.record_mutation_authorization(base.task_id, auth, now="2026-10-01T10:30:00Z")
        self.assertEqual(store.load(base.task_id), result)
        self.assertEqual(result.mutation_proposal, proposal)
        self.assertEqual(result.mutation_authorization, auth)

    def test_mutation_persistence_rejects_wrong_task_key_without_write(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError
        from engineering_gate_core.models import MutationProposal, NormalizedOperation, OperationKind
        from engineering_gate_core.workflow import mutation_argument_digest
        store = StateStore(self.path)
        store.create(self.record)
        invalid = MutationProposal("p", "other", 1, "0" * 64,
                                   NormalizedOperation(OperationKind.WRITE, "a", "write"),
                                   mutation_argument_digest("x"), "write")
        before = store.load("task-1")
        with self.assertRaises(StateStoreError):
            store.record_mutation_proposal("other", invalid)
        self.assertEqual(store.load("task-1"), before)

    def test_invalid_or_expired_authorization_rolls_back_without_changing_record(self):
        from dataclasses import replace
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError, _record_json
        from engineering_gate_core.models import (AcceptanceCriterion, ApprovalReceipt, ApprovalRequest,
            ExecutionPermit, MutationAuthorization, MutationProposal, MutationScope, NormalizedOperation,
            OperationKind, Plan, PlanRevision, PlanReview, ReviewVerdict)
        from engineering_gate_core.workflow import (canonical_mutation_proposal_digest, canonical_plan_digest,
            capture_workspace_identity, mutation_argument_digest, record_mutation_proposal, TransitionError)
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "update")
        root = str(Path(self.temp.name).resolve())
        plan = Plan("inspect project", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",),
            workspace_root=root, workspace_identity=capture_workspace_identity(root))
        digest = canonical_plan_digest(plan)
        current = replace(self.record, state=TaskState.IMPLEMENTING, revision=PlanRevision(1), plan=plan,
            plan_digest=digest, plan_review=PlanReview(ReviewVerdict.APPROVED),
            approval_request=ApprovalRequest(self.record.task_id, 1, digest, "r"),
            approval=ApprovalReceipt("r", self.record.task_id, 1, digest, self.record.task.requester, True),
            permit=ExecutionPermit(self.record.task_id, 1, digest, MutationScope((op,))))
        proposal = MutationProposal("p", self.record.task_id, 1, digest, op, mutation_argument_digest("x"), "write")
        current = record_mutation_proposal(current, proposal)
        valid = MutationAuthorization("a", self.record.task_id, 1, digest,
            canonical_mutation_proposal_digest(proposal), "provider", "2026-10-01T10:00:00Z", "2026-10-01T11:00:00Z")
        store = StateStore(self.path)
        store.create(self.record)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE task_state SET payload=? WHERE task_id=?", (_record_json(current), self.record.task_id))
        before = store.load(self.record.task_id)
        for auth, now in ((valid, "2026-10-01T11:00:00Z"),
                          (replace(valid, proposal_digest="0" * 64), "2026-10-01T10:30:00Z")):
            with self.subTest(auth=auth), self.assertRaises(TransitionError):
                store.record_mutation_authorization(self.record.task_id, auth, now=now)
            self.assertEqual(store.load(self.record.task_id), before)

    def test_ill_typed_record_fails_closed(self):
        import json
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        store = StateStore(self.path)
        store.create(self.record)
        with sqlite3.connect(self.path) as db:
            (payload,) = db.execute("SELECT payload FROM task_state WHERE task_id='task-1'").fetchone()
            value = json.loads(payload)
            value["state"] = "inspect"
            db.execute("UPDATE task_state SET payload=? WHERE task_id='task-1'", (json.dumps(value),))
        with self.assertRaises(StateStoreError):
            store.load("task-1")

    def test_partial_metadata_schema_fails_closed(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        with self.assertRaises(StateStoreError):
            StateStore(self.path).load("task-1")

    def test_existing_schema_without_metadata_table_fails_closed(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE unrelated (value TEXT)")
        with self.assertRaises(StateStoreError):
            StateStore(self.path).load("task-1")

    def test_duplicate_schema_version_rows_fail_closed(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE metadata (key TEXT, value TEXT)")
            db.executemany("INSERT INTO metadata VALUES (?, ?)", [
                ("schema_version", "1"), ("schema_version", "1")
            ])
            db.execute("CREATE TABLE task_state (task_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        with self.assertRaises(StateStoreError):
            StateStore(self.path).load("task-1")

    def test_v1_schema_missing_task_state_payload_fails_closed_before_crud(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO metadata VALUES ('schema_version', '1')")
            db.execute("CREATE TABLE task_state (task_id TEXT PRIMARY KEY)")
        import os
        os.chmod(self.path, 0o600)

        with self.assertRaises(StateStoreError):
            StateStore(self.path).create(self.record)

    def test_v1_schema_with_generated_column_fails_closed_before_crud(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO metadata VALUES ('schema_version', '1')")
            db.execute("CREATE TABLE task_state (task_id TEXT PRIMARY KEY, payload TEXT NOT NULL, extra TEXT GENERATED ALWAYS AS (payload) VIRTUAL)")
        import os
        os.chmod(self.path, 0o600)

        with self.assertRaises(StateStoreError):
            StateStore(self.path).create(self.record)

    def test_v1_schema_without_task_id_uniqueness_fails_closed_before_crud(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO metadata VALUES ('schema_version', '1')")
            db.execute("CREATE TABLE task_state (task_id TEXT, payload TEXT NOT NULL)")
        import os
        os.chmod(self.path, 0o600)

        with self.assertRaises(StateStoreError):
            StateStore(self.path).create(self.record)


    @unittest.skipUnless(__import__("os").name == "posix", "POSIX permissions only")
    def test_existing_unsafe_writable_parent_is_rejected(self):
        import os
        from engineering_gate_core.state_store import StateStore, StateStoreError

        os.chmod(self.temp.name, 0o777)
        with self.assertRaises(StateStoreError):
            StateStore(self.path)

    @unittest.skipUnless(__import__("os").name == "posix", "POSIX permissions only")
    def test_existing_database_with_broad_mode_is_rejected_without_chmod(self):
        import os
        import stat
        from engineering_gate_core.state_store import StateStore, StateStoreError

        self.path.touch()
        os.chmod(self.path, 0o644)
        with self.assertRaises(StateStoreError):
            StateStore(self.path)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)

    @unittest.skipUnless(__import__("os").name == "posix", "POSIX symlinks only")
    def test_symlinked_database_parent_is_rejected_without_touching_target(self):
        from engineering_gate_core.state_store import StateStore, StateStoreError

        target_dir = Path(self.temp.name) / "real"
        target_dir.mkdir()
        target = target_dir / "state.sqlite3"
        link = Path(self.temp.name) / "linked"
        link.symlink_to(target_dir, target_is_directory=True)
        with self.assertRaises(StateStoreError):
            StateStore(link / "state.sqlite3")
        self.assertFalse(target.exists())

    def test_state_transaction_blocks_transition_until_callback_returns(self):
        import threading
        from engineering_gate_core.state_store import StateStore
        from engineering_gate_core.workflow import Event

        store = StateStore(self.path)
        store.create(self.record)
        entered = threading.Event()
        release = threading.Event()
        transitioned = threading.Event()
        errors = []

        def callback(current):
            self.assertEqual(current, self.record)
            entered.set()
            if not release.wait(2):
                raise AssertionError("test did not release callback")

        def transact():
            try:
                store.with_current_state_transaction("task-1", callback)
            except Exception as exc:
                errors.append(exc)

        def change_state():
            try:
                store.transition("task-1", Event.CANCEL)
                transitioned.set()
            except Exception as exc:
                errors.append(exc)

        tx = threading.Thread(target=transact)
        tx.start()
        self.assertTrue(entered.wait(2))
        changer = threading.Thread(target=change_state)
        changer.start()
        self.assertFalse(transitioned.wait(0.1))
        release.set()
        tx.join(2)
        changer.join(2)
        self.assertFalse(tx.is_alive())
        self.assertFalse(changer.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(transitioned.is_set())

    def test_state_transaction_callback_exception_rolls_back_and_unlocks(self):
        from engineering_gate_core.state_store import StateStore
        from engineering_gate_core.workflow import Event

        store = StateStore(self.path)
        store.create(self.record)

        def callback(current):
            self.assertEqual(current, self.record)
            raise ValueError("protected mutation failed")

        with self.assertRaisesRegex(ValueError, "protected mutation failed"):
            store.with_current_state_transaction("task-1", callback)
        self.assertEqual(store.load("task-1"), self.record)
        self.assertEqual(store.transition("task-1", Event.CANCEL).state, TaskState.CANCELLED)

    def test_concurrent_first_open_initializes_schema_once(self):
        import threading
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        stores = [StateStore(self.path) for _ in range(8)]
        barrier = threading.Barrier(len(stores))
        errors = []

        def open_and_use(store):
            barrier.wait()
            try:
                store.load("missing")
            except StateStoreError as exc:
                if str(exc) != "task not found":
                    errors.append(exc)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=open_and_use, args=(store,)) for store in stores]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        with sqlite3.connect(self.path) as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"metadata", "task_state"}.issubset(tables))

    def test_execution_audit_transaction_is_persisted_and_append_only(self):
        from dataclasses import replace
        from datetime import datetime, timezone
        from engineering_gate_core.models import (AcceptanceCriterion, ApprovalReceipt, ApprovalRequest,
            ExecutionAuditRecord, ExecutionOutcome, ExecutionPermit, ExecutionTransactionResult,
            MutationAuthorization, MutationProposal, MutationScope, NormalizedOperation, OperationKind,
            Plan, PlanReview, PlanRevision, ReviewVerdict)
        from engineering_gate_core.state_store import StateStore, StateStoreError
        from engineering_gate_core.workflow import (canonical_mutation_proposal_digest, canonical_plan_digest,
            capture_workspace_identity, mutation_argument_digest, record_mutation_proposal)
        import sqlite3
        store = StateStore(self.path)
        store.create(self.record)
        op = __import__("engineering_gate_core.models", fromlist=["NormalizedOperation"]).NormalizedOperation(OperationKind.WRITE, "output.txt")
        root = str(Path(self.temp.name).resolve())
        plan = Plan("inspect project", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",),
                    workspace_root=root, workspace_identity=capture_workspace_identity(root))
        digest = canonical_plan_digest(plan)
        current = replace(self.record, state=TaskState.IMPLEMENTING, revision=PlanRevision(1), plan=plan,
            plan_digest=digest, plan_review=PlanReview(ReviewVerdict.APPROVED),
            approval_request=ApprovalRequest(self.record.task_id, 1, digest, "r"),
            approval=ApprovalReceipt("r", self.record.task_id, 1, digest, self.record.task.requester, True),
            permit=ExecutionPermit(self.record.task_id, 1, digest, MutationScope((op,))))
        proposal = MutationProposal("p", self.record.task_id, 1, digest, op, mutation_argument_digest("hello"), "write")
        current = record_mutation_proposal(current, proposal)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        stamp = now.isoformat().replace("+00:00", "Z")
        authorization = MutationAuthorization("a", self.record.task_id, 1, digest,
            canonical_mutation_proposal_digest(proposal), "provider", stamp,
            (now.replace(year=now.year + 1)).isoformat().replace("+00:00", "Z"))
        current = replace(current, mutation_authorization=authorization)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE task_state SET payload=? WHERE task_id=?", (__import__("engineering_gate_core.state_store", fromlist=["_record_json"])._record_json(current), self.record.task_id))
        ws = plan.workspace_identity
        audit = ExecutionAuditRecord("audit-1", self.record.task_id, 1, digest, authorization.proposal_digest,
            "a", "1" * 64, OperationKind.WRITE, "output.txt", proposal.argument_digest, ws,
            stamp, stamp, ExecutionOutcome.SUCCEEDED, "2" * 64)
        result = ExecutionTransactionResult(audit, False)
        store.with_current_state_transaction(self.record.task_id, lambda _: result)
        self.assertEqual(store.list_execution_audits(self.record.task_id), (audit,))

        # A persisted audit cannot claim a proposal operation unless the current
        # one-shot Gate permit still scopes that exact operation and revision.
        wrong_permit = replace(current.permit, scope=MutationScope(()))
        invalid_current = replace(current, permit=wrong_permit)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE task_state SET payload=? WHERE task_id=?", (
                __import__("engineering_gate_core.state_store", fromlist=["_record_json"])._record_json(invalid_current),
                self.record.task_id))
        with self.assertRaises(StateStoreError):
            store.with_current_state_transaction(self.record.task_id, lambda _: ExecutionTransactionResult(
                replace(audit, audit_id="bad-permit-scope"), False))
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE task_state SET payload=? WHERE task_id=?", (
                __import__("engineering_gate_core.state_store", fromlist=["_record_json"])._record_json(current),
                self.record.task_id))
        # Envelope fields must match the current state, proposal, and permit.
        for changed in (
            replace(audit, proposal_digest="9" * 64, audit_id="bad-proposal"),
            replace(audit, authorization_id="different", audit_id="bad-auth"),
            replace(audit, task_id="other-task", audit_id="bad-task"),
            replace(audit, revision=2, audit_id="bad-revision"),
            replace(audit, plan_digest="8" * 64, audit_id="bad-plan"),
            replace(audit, target="other.txt", audit_id="bad-target"),
            replace(audit, argument_digest="7" * 64, audit_id="bad-argument"),
        ):
            with self.subTest(audit=changed), self.assertRaises(StateStoreError):
                store.with_current_state_transaction(self.record.task_id,
                    lambda _, changed=changed: ExecutionTransactionResult(changed, False))
        with sqlite3.connect(self.path) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("UPDATE execution_audit SET target='changed' WHERE audit_id='audit-1'")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM execution_audit WHERE audit_id='audit-1'")
        duplicate = replace(audit, audit_id="audit-2", permit_hash="1" * 64)
        with self.assertRaises(sqlite3.IntegrityError):
            store.with_current_state_transaction(self.record.task_id,
                lambda _: ExecutionTransactionResult(duplicate, False))

    def test_v1_payload_is_canonicalized_without_changing_typed_state(self):
        import json
        import sqlite3
        from engineering_gate_core.state_store import StateStore

        StateStore(self.path).create(self.record)
        with sqlite3.connect(self.path) as db:
            (payload,) = db.execute("SELECT payload FROM task_state").fetchone()
            db.execute("UPDATE task_state SET payload=?", (json.dumps(json.loads(payload), indent=2),))
            db.execute("UPDATE metadata SET value='1' WHERE key='schema_version'")
        reopened = StateStore(self.path)
        self.assertEqual(reopened.load("task-1"), self.record)
        with sqlite3.connect(self.path) as db:
            (payload,) = db.execute("SELECT payload FROM task_state").fetchone()
            self.assertEqual(payload, __import__("engineering_gate_core.state_store", fromlist=["_record_json"])._record_json(self.record))

    def test_v1_rejects_legacy_approval_without_plan_atomically(self):
        import sqlite3, json
        from dataclasses import replace
        from engineering_gate_core.state_store import StateStore, StateStoreError, _record_json
        from engineering_gate_core.models import ApprovalReceipt, ApprovalRequest, PlanDigest, PlanRevision
        store = StateStore(self.path)
        store.create(self.record)
        approved_without_plan = replace(self.record, approval_request=ApprovalRequest(
            self.record.task_id, PlanRevision(1), PlanDigest("0" * 64), "request"),
            approval=ApprovalReceipt("request", self.record.task_id, PlanRevision(1),
                                     PlanDigest("0" * 64), self.record.task.requester, True))
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE task_state SET payload=?", (_record_json(approved_without_plan),))
            db.execute("UPDATE metadata SET value='1' WHERE key='schema_version'")
        with self.assertRaises(StateStoreError):
            StateStore(self.path).load("task-1")
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0], "1")
            self.assertEqual(db.execute("SELECT payload FROM task_state").fetchone()[0], _record_json(approved_without_plan))

    def test_v1_migration_rejects_key_mismatch_atomically(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        StateStore(self.path).create(self.record)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE task_state SET payload='{}' WHERE task_id='task-1'")
            db.execute("UPDATE metadata SET value='1' WHERE key='schema_version'")
        with self.assertRaises(StateStoreError):
            StateStore(self.path).load("task-1")
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0], "1")
            self.assertEqual(db.execute("SELECT payload FROM task_state WHERE task_id='task-1'").fetchone()[0], "{}")

    def test_audit_schema_rejects_incompatible_existing_table(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError

        StateStore(self.path).create(self.record)
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TABLE execution_audit")
            db.execute("CREATE TABLE execution_audit (audit_id TEXT)")
        with self.assertRaises(StateStoreError):
            StateStore(self.path).load("task-1")

    def test_v1_database_migrates_atomically_to_v2(self):
        import sqlite3
        import json
        from engineering_gate_core.state_store import StateStore
        store = StateStore(self.path)
        store.create(self.record)
        with sqlite3.connect(self.path) as db:
            (payload,) = db.execute("SELECT payload FROM task_state WHERE task_id='task-1'").fetchone()
            raw = json.loads(payload)
            for key in ("mutation_authorization", "mutation_proposal"):
                raw.pop(key, None)
            db.execute("UPDATE task_state SET payload=? WHERE task_id='task-1'", (json.dumps(raw),))
            db.execute("UPDATE metadata SET value='1' WHERE key='schema_version'")
        reopened = StateStore(self.path)
        self.assertEqual(reopened.load("task-1"), self.record)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0], "2")
            self.assertTrue(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='execution_audit'").fetchone())

    def test_v1_tagged_nested_plan_missing_identity_is_invalidated_only(self):
        import json, sqlite3
        from dataclasses import replace
        from engineering_gate_core.state_store import StateStore, _record_json
        from engineering_gate_core.models import Plan, AcceptanceCriterion, NormalizedOperation, OperationKind
        from engineering_gate_core.workflow import canonical_plan_digest
        store = StateStore(self.path)
        store.create(self.record)
        plan = Plan("inspect", (NormalizedOperation(OperationKind.READ, "a"),),
                    (AcceptanceCriterion("c", "ok", "test"),), ("test",), workspace_root="/tmp")
        advanced = replace(self.record, state=TaskState.PLAN, plan=plan, plan_digest=canonical_plan_digest(plan),
                           analysis=__import__("engineering_gate_core.models", fromlist=["Evidence"]).Evidence("e", "summary"))
        raw = json.loads(_record_json(advanced))
        raw["plan"].pop("workspace_identity")
        raw.pop("mutation_authorization")
        raw.pop("mutation_proposal")
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE task_state SET payload=?", (json.dumps(raw),))
            db.execute("UPDATE metadata SET value='1' WHERE key='schema_version'")
        loaded = StateStore(self.path).load("task-1")
        self.assertEqual(loaded.analysis, advanced.analysis)
        self.assertEqual(loaded.plan, plan)
        self.assertIsNone(loaded.plan.workspace_identity)
        self.assertEqual(int(loaded.revision), int(advanced.revision) + 1)
        self.assertEqual(loaded.state, TaskState.PLAN)
        self.assertIsNone(loaded.approval)
        self.assertIsNone(loaded.approval_request)
        self.assertIsNone(loaded.plan_review)
        self.assertEqual(loaded.plan_digest, canonical_plan_digest(plan))

    def test_v1_tagged_plan_missing_only_mutation_fields_preserves_approval(self):
        import json, sqlite3
        from dataclasses import replace
        from engineering_gate_core.state_store import StateStore, _record_json
        from engineering_gate_core.models import (Plan, AcceptanceCriterion, NormalizedOperation, OperationKind,
            PlanDigest, PlanRevision, ApprovalRequest, ApprovalReceipt, PlanReview, ReviewVerdict)
        from engineering_gate_core.workflow import canonical_plan_digest
        store = StateStore(self.path); store.create(self.record)
        plan = Plan("inspect", (NormalizedOperation(OperationKind.READ, "a"),),
                    (AcceptanceCriterion("c", "ok", "test"),), ("test",), workspace_root="/tmp",
                    workspace_identity=__import__("engineering_gate_core.workflow", fromlist=["capture_workspace_identity"]).capture_workspace_identity("/tmp"))
        digest = canonical_plan_digest(plan)
        approved = replace(self.record, state=TaskState.APPROVED, revision=PlanRevision(1), plan=plan,
            plan_digest=digest, plan_review=PlanReview(ReviewVerdict.APPROVED),
            approval_request=ApprovalRequest(self.record.task_id, 1, digest, "req"),
            approval=ApprovalReceipt("req", self.record.task_id, 1, digest, self.record.task.requester, True))
        raw = json.loads(_record_json(approved)); raw.pop("mutation_authorization"); raw.pop("mutation_proposal")
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE task_state SET payload=?", (json.dumps(raw),)); db.execute("UPDATE metadata SET value='1'")
        loaded = StateStore(self.path).load("task-1")
        self.assertEqual(loaded.approval, approved.approval)
        self.assertEqual(loaded.state, TaskState.APPROVED)

    def test_v1_migration_rejects_untagged_and_unknown_fields(self):
        import json, sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError
        store = StateStore(self.path); store.create(self.record)
        with sqlite3.connect(self.path) as db:
            raw=json.loads(db.execute("SELECT payload FROM task_state").fetchone()[0]); raw.pop("$type")
            db.execute("UPDATE task_state SET payload=?", (json.dumps(raw),)); db.execute("UPDATE metadata SET value='1'")
        with self.assertRaises(StateStoreError): StateStore(self.path).load("task-1")

    def test_audit_schema_rejects_noop_named_trigger(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError
        StateStore(self.path).create(self.record)
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER execution_audit_no_update")
            db.execute("CREATE TRIGGER execution_audit_no_update BEFORE UPDATE ON execution_audit BEGIN SELECT 1; END")
        with self.assertRaises(StateStoreError): StateStore(self.path).load("task-1")

    def test_audit_schema_rejects_conditionally_weakened_same_name_trigger(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError
        StateStore(self.path).create(self.record)
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER execution_audit_no_update")
            db.execute("CREATE TRIGGER execution_audit_no_update BEFORE UPDATE ON execution_audit WHEN NEW.target != OLD.target BEGIN SELECT RAISE(ABORT,'append-only'); END")
        with self.assertRaises(StateStoreError): StateStore(self.path).load("task-1")

    def test_audit_schema_rejects_wrong_column_same_name_index(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError
        StateStore(self.path).create(self.record)
        with sqlite3.connect(self.path) as db:
            db.execute("DROP INDEX execution_audit_task_idx")
            db.execute("CREATE INDEX execution_audit_task_idx ON execution_audit(revision, task_id)")
        with self.assertRaises(StateStoreError): StateStore(self.path).load("task-1")

    def test_audit_schema_rejects_extra_index(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError
        StateStore(self.path).create(self.record)
        with sqlite3.connect(self.path) as db: db.execute("CREATE INDEX unexpected ON execution_audit(target)")
        with self.assertRaises(StateStoreError): StateStore(self.path).load("task-1")

    def test_audit_model_rejects_naive_timestamps(self):
        from engineering_gate_core.models import (ExecutionAuditRecord, ExecutionOutcome,
            OperationKind, WorkspaceIdentity)
        valid = dict(audit_id="audit-1", task_id="task-1", revision=0,
            plan_digest="0" * 64, proposal_digest="1" * 64,
            authorization_id="auth-1", permit_hash="2" * 64,
            operation_kind=OperationKind.WRITE, target="output.txt",
            argument_digest="3" * 64, workspace_identity=WorkspaceIdentity("/workspace", 1, 2),
            started_at="2026-10-01T10:00:00", completed_at="2026-10-01T10:01:00Z",
            outcome=ExecutionOutcome.OUTCOME_UNKNOWN)
        with self.assertRaises(ValueError):
            ExecutionAuditRecord(**valid)

    def test_execution_transaction_envelope_rejects_non_boolean_detachment(self):
        from engineering_gate_core.models import ExecutionTransactionResult
        with self.assertRaises(ValueError):
            ExecutionTransactionResult(None, 1)

    def test_v2_decoder_rejects_missing_mutation_fields(self):
        import json
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError
        StateStore(self.path).create(self.record)
        with sqlite3.connect(self.path) as db:
            raw = json.loads(db.execute("SELECT payload FROM task_state").fetchone()[0])
            raw.pop("mutation_proposal")
            db.execute("UPDATE task_state SET payload=?", (json.dumps(raw),))
        with self.assertRaises(StateStoreError):
            StateStore(self.path).load("task-1")

    def test_audit_schema_rejects_weakened_checks(self):
        import sqlite3
        from engineering_gate_core.state_store import StateStore, StateStoreError
        StateStore(self.path).create(self.record)
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TABLE execution_audit")
            db.execute("CREATE TABLE execution_audit (audit_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES task_state(task_id), revision INTEGER NOT NULL, plan_digest TEXT NOT NULL, proposal_digest TEXT NOT NULL, authorization_id TEXT NOT NULL, permit_hash TEXT NOT NULL UNIQUE, operation_kind TEXT NOT NULL CHECK(operation_kind='write'), target TEXT NOT NULL, argument_digest TEXT NOT NULL, workspace_identity TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT NOT NULL, outcome TEXT NOT NULL CHECK(outcome IN ('succeeded','outcome_unknown')), resulting_artifact_digest TEXT, path_detached INTEGER NOT NULL CHECK(path_detached IN (0,1)), error_class TEXT, CHECK(1))")
        with self.assertRaises(StateStoreError):
            StateStore(self.path).load("task-1")

    def test_execution_audit_requires_canonical_timestamps_and_outcome(self):
        from engineering_gate_core.models import ExecutionAuditRecord, ExecutionOutcome, OperationKind, WorkspaceIdentity
        fields = dict(audit_id="audit-1", task_id="task-1", revision=0,
            plan_digest="0" * 64, proposal_digest="1" * 64, authorization_id="auth-1",
            permit_hash="2" * 64, operation_kind=OperationKind.WRITE, target="output.txt",
            argument_digest="3" * 64, workspace_identity=WorkspaceIdentity("/workspace", 1, 2),
            started_at="2026-10-01T10:00:00Z", completed_at="2026-10-01T10:01:00Z",
            outcome=ExecutionOutcome.OUTCOME_UNKNOWN)
        for changed in (dict(started_at="2026-10-01T10:00:00+00:00"),
                        dict(completed_at="2026-10-01T10:01:00.000Z"),
                        dict(outcome="outcome_unknown")):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                ExecutionAuditRecord(**(fields | changed))


if __name__ == "__main__":
    unittest.main()
