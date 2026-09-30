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


if __name__ == "__main__":
    unittest.main()
