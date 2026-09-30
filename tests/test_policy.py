import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.models import (
    AcceptanceCriterion, ApprovalReceipt, ExecutionPermit, MutationScope,
    NormalizedOperation, OperationKind, Plan, PlanDigest, PlanRevision,
    RequesterIdentity, TaskState, TaskStateRecord,
)
from engineering_gate_core.workflow import canonical_plan_digest
from engineering_gate_core.policy import PolicyAction, authorize_invocation


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self._workspace = tempfile.TemporaryDirectory()
        self.workspace_root = str(Path(self._workspace.name).resolve())
        self.requester = RequesterIdentity("alice")
        self.op = NormalizedOperation(OperationKind.WRITE, "src/file.py", "update")
        self.plan = Plan("change", (self.op,), (AcceptanceCriterion("a", "works", "test"),), ("run tests",), workspace_root=self.workspace_root)
        digest = canonical_plan_digest(self.plan)
        self.state = TaskStateRecord(
            task=__import__("engineering_gate_core.models", fromlist=["Task"]).Task("task-1", "change", self.requester),
            state=TaskState.IMPLEMENTING, revision=PlanRevision(2), history=(), plan=self.plan,
            plan_digest=digest,
            approval=ApprovalReceipt("req", "task-1", PlanRevision(2), digest, self.requester, True),
            permit=ExecutionPermit("task-1", PlanRevision(2), digest, MutationScope((self.op,))),
        )

    def tearDown(self):
        self._workspace.cleanup()

    def test_allows_exact_approved_and_permitted_operation(self):
        decision = authorize_invocation(self.state, self.op, self.workspace_root)
        self.assertEqual(decision.action, PolicyAction.ALLOW)

    def test_blocks_wrong_state(self):
        from dataclasses import replace
        result = authorize_invocation(replace(self.state, state=TaskState.APPROVED), self.op, self.workspace_root)
        self.assertEqual(result.action, PolicyAction.BLOCK)

    def test_blocks_stale_approval_and_permit_bindings(self):
        from dataclasses import replace
        from engineering_gate_core.models import ApprovalReceipt, ExecutionPermit
        cases = (
            replace(self.state, approval=replace(self.state.approval, revision=PlanRevision(1))),
            replace(self.state, approval=replace(self.state.approval, digest=PlanDigest("stale"))),
            replace(self.state, permit=replace(self.state.permit, revision=PlanRevision(1))),
            replace(self.state, permit=replace(self.state.permit, digest=PlanDigest("stale"))),
        )
        for state in cases:
            with self.subTest(state=state):
                self.assertEqual(authorize_invocation(state, self.op, self.workspace_root).action, PolicyAction.BLOCK)

    def test_unplanned_operation_blocks(self):
        other = NormalizedOperation(OperationKind.WRITE, "src/other.py", "other")
        self.assertEqual(authorize_invocation(self.state, other, self.workspace_root).action, PolicyAction.BLOCK)

    def test_planned_but_out_of_scope_operation_reports_scope_drift(self):
        from dataclasses import replace
        other = NormalizedOperation(OperationKind.WRITE, "src/other.py", "other")
        plan = Plan("change", (self.op, other), self.plan.acceptance_criteria, self.plan.verification, workspace_root=self.workspace_root)
        from engineering_gate_core.models import ExecutionPermit, MutationScope
        from engineering_gate_core.workflow import canonical_plan_digest
        digest = canonical_plan_digest(plan)
        state = replace(self.state, plan=plan, plan_digest=digest,
                        approval=replace(self.state.approval, digest=digest),
                        permit=replace(self.state.permit, digest=digest, scope=MutationScope((self.op,))))
        self.assertEqual(authorize_invocation(state, other, self.workspace_root).action, PolicyAction.SCOPE_DRIFT)

    def test_rejects_absolute_and_traversal_targets(self):
        for target in ("/etc/passwd", "../outside", "src/../outside", "C:\\\\outside", f"src{chr(92)}file.py", "."):
            op = NormalizedOperation(OperationKind.WRITE, target, "bad")
            state = __import__("dataclasses").replace(
                self.state, plan=Plan(self.plan.objective, (op,), self.plan.acceptance_criteria, self.plan.verification, workspace_root=self.workspace_root),
                plan_digest=None)
            from engineering_gate_core.workflow import canonical_plan_digest
            digest = canonical_plan_digest(state.plan)
            state = __import__("dataclasses").replace(state, plan_digest=digest,
                approval=__import__("dataclasses").replace(state.approval, digest=digest),
                permit=__import__("dataclasses").replace(state.permit, digest=digest,
                    scope=__import__("engineering_gate_core.models", fromlist=["MutationScope"]).MutationScope((op,))))
            with self.subTest(target=target):
                self.assertEqual(authorize_invocation(state, op, self.workspace_root).action, PolicyAction.BLOCK)

    def test_rejects_symlink_escape(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            Path(root, "escape").symlink_to(outside, target_is_directory=True)
            op = NormalizedOperation(OperationKind.WRITE, "escape/file", "bad")
            plan = Plan(self.plan.objective, (op,), self.plan.acceptance_criteria, self.plan.verification,
                        workspace_root=str(Path(root).resolve()))
            from engineering_gate_core.workflow import canonical_plan_digest
            digest = canonical_plan_digest(plan)
            state = replace(self.state, plan=plan, plan_digest=digest,
                approval=replace(self.state.approval, digest=digest),
                permit=replace(self.state.permit, digest=digest,
                    scope=__import__("engineering_gate_core.models", fromlist=["MutationScope"]).MutationScope((op,))))
            result = authorize_invocation(state, op, root)
            self.assertEqual(result.action, PolicyAction.BLOCK)
            self.assertIn("target is invalid", result.reason)

    def test_rejects_symlink_alias_inside_workspace(self):
        from dataclasses import replace
        from engineering_gate_core.models import MutationScope
        from engineering_gate_core.workflow import canonical_plan_digest
        with tempfile.TemporaryDirectory() as root:
            Path(root, "src", "real").mkdir(parents=True)
            Path(root, "src", "alias").symlink_to(Path(root, "src", "real"), target_is_directory=True)
            op = NormalizedOperation(OperationKind.WRITE, "src/alias/file.py", "redirect")
            plan = Plan(self.plan.objective, (op,), self.plan.acceptance_criteria, self.plan.verification,
                        workspace_root=str(Path(root).resolve()))
            digest = canonical_plan_digest(plan)
            state = replace(self.state, plan=plan, plan_digest=digest,
                approval=replace(self.state.approval, digest=digest),
                permit=replace(self.state.permit, digest=digest, scope=MutationScope((op,))))
            result = authorize_invocation(state, op, root)
            self.assertEqual(result.action, PolicyAction.BLOCK)
            self.assertIn("target is invalid", result.reason)

    def test_denies_execute_and_unknown(self):
        for kind in (OperationKind.EXECUTE, OperationKind.UNKNOWN):
            op = NormalizedOperation(kind, "", "unsupported")
            self.assertEqual(authorize_invocation(self.state, op, self.workspace_root).action, PolicyAction.BLOCK)

    def test_invalid_workspace_blocks(self):
        self.assertEqual(authorize_invocation(self.state, self.op, "/path/that/does/not/exist").action,
                         PolicyAction.BLOCK)

    def test_plan_digest_binds_workspace_root(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            left = replace(self.plan, workspace_root=str(Path(first).resolve()))
            right = replace(self.plan, workspace_root=str(Path(second).resolve()))
            self.assertNotEqual(canonical_plan_digest(left), canonical_plan_digest(right))

    def test_blocks_caller_supplied_alternate_workspace(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as approved, tempfile.TemporaryDirectory() as alternate:
            plan = replace(self.plan, workspace_root=str(Path(approved).resolve()))
            digest = canonical_plan_digest(plan)
            state = replace(self.state, plan=plan, plan_digest=digest,
                            approval=replace(self.state.approval, digest=digest),
                            permit=replace(self.state.permit, digest=digest))
            self.assertEqual(authorize_invocation(state, self.op, alternate).action, PolicyAction.BLOCK)


if __name__ == "__main__":
    unittest.main()
