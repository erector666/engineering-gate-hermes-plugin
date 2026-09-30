import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.a3_execution import GateWriteService


class GateOwnedWriteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.service = GateWriteService(self.root)

    def permit(self, **overrides):
        values = {
            "task": "task-1",
            "plan_revision": "rev-1",
            "operation": "write",
            "target": "approved.txt",
            "arguments": {"content": "approved"},
        }
        values.update(overrides)
        return self.service.issue_permit(**values)

    def request(self, permit, **overrides):
        values = {
            "task": "task-1",
            "plan_revision": "rev-1",
            "operation": "write",
            "target": "approved.txt",
            "arguments": {"content": "approved"},
        }
        values.update(overrides)
        return self.service.execute(permit, **values)

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
            self.request(permit, task="other-task")

    def test_plan_revision_mismatch_is_rejected(self):
        permit = self.permit()
        with self.assertRaises(PermissionError):
            self.request(permit, plan_revision="rev-2")

    def test_operation_mismatch_is_rejected(self):
        permit = self.permit()
        with self.assertRaises(PermissionError):
            self.request(permit, operation="delete")

    def test_permit_replay_is_rejected(self):
        permit = self.permit()
        self.request(permit)
        with self.assertRaises(PermissionError):
            self.request(permit)

    def test_unknown_operation_cannot_be_permitted(self):
        with self.assertRaises(ValueError):
            self.permit(operation="unknown")

    def test_parent_traversal_is_rejected(self):
        permit = self.permit(target="../outside.txt")
        with self.assertRaises(PermissionError):
            self.request(permit, target="../outside.txt")
        self.assertFalse((self.root.parent / "outside.txt").exists())

    def test_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            (self.root / "escape").symlink_to(outside, target_is_directory=True)
            permit = self.permit(target="escape/file.txt")
            with self.assertRaises(PermissionError):
                self.request(permit, target="escape/file.txt")
            self.assertFalse((Path(outside) / "file.txt").exists())


if __name__ == "__main__":
    unittest.main()
