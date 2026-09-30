import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.models import (AcceptanceCriterion, ApprovalReceipt, ApprovalRequest, Evidence, ExecutionPermit, Handoff, InspectionEvidenceRef, MutationScope, NormalizedOperation, OperationKind, Plan, PlanDigest, PlanReview, PlanRevision, RequesterIdentity, ResultReview, ReviewVerdict, TaskState, TaskStateRecord, VerificationResult)
from engineering_gate_core.workflow import Stage, new_task, transition, Event, TransitionError, record_approval, revise_plan, canonical_plan_digest


class WorkflowTests(unittest.TestCase):
    def test_new_task_records_intake_and_enters_inspection(self):
        task = new_task("task-1", "Add a feature", RequesterIdentity("user-1"))
        self.assertEqual(task.state, Stage.INSPECT)
        self.assertEqual(task.task_id, "task-1")
        self.assertEqual(task.history[-1], Stage.INSPECT)
        self.assertEqual(task.revision, 0)

    def test_inspection_evidence_advances_to_analysis(self):
        task = new_task("task-1", "Add a feature", RequesterIdentity("user-1"))
        task = transition(task, Event.INSPECTION_RECORDED,
                         InspectionEvidenceRef("ev-1", "baseline snapshot"))
        self.assertEqual(task.state, TaskState.ANALYZE)
        self.assertEqual(task.inspection.evidence_id, "ev-1")
    def test_approved_lifecycle_reaches_completed_without_skipping(self):
        task = new_task("task-2", "Add feature", RequesterIdentity("user-2"))
        task = transition(task, Event.INSPECTION_RECORDED, InspectionEvidenceRef("i", "baseline"))
        task = transition(task, Event.ANALYSIS_RECORDED, Evidence("a", "findings"))
        operation = NormalizedOperation(OperationKind.WRITE, "src/new.py")
        criterion = AcceptanceCriterion("AC-1", "Feature works", "run unit tests")
        plan = Plan("Add feature", (operation,), (criterion,), ("run unit tests",))
        task = transition(task, Event.PLAN_RECORDED, plan)
        task = transition(task, Event.BLAST_RADIUS_RECORDED, Evidence("b", "impact"))
        task = transition(task, Event.PLAN_REVIEW_PASSED, PlanReview(ReviewVerdict.APPROVED))
        request = ApprovalRequest(task.task_id, task.revision, task.plan_digest, "request")
        task = transition(task, Event.APPROVAL_REQUESTED, request)
        receipt = ApprovalReceipt("request", task.task_id, task.revision, task.plan_digest, task.task.requester, True)
        task = record_approval(task, receipt)
        permit = ExecutionPermit(task.task_id, task.revision, task.plan_digest, MutationScope((operation,)))
        task = transition(task, Event.IMPLEMENTATION_STARTED, permit)
        result = VerificationResult("AC-1", (Evidence("check", "tests passed", True),), True)
        task = transition(task, Event.VERIFICATION_RECORDED, (result,))
        task = transition(task, Event.RESULT_REVIEW_PASSED, ResultReview(ReviewVerdict.PASS))
        task = transition(task, Event.HANDOFF_RECORDED, Handoff("Implemented and verified", (Evidence("h", "reviewed"),)))
        self.assertEqual(task.state, TaskState.COMPLETED)
        self.assertEqual(task.verification, (result,))

    def test_approval_receipt_must_match_requester_and_plan_binding(self):
        task = new_task("task-3", "Add feature", RequesterIdentity("requester"))
        task = TaskStateRecord(task.task, TaskState.AWAITING_APPROVAL, task.revision,
                               task.history + (TaskState.ANALYZE, TaskState.PLAN, TaskState.BLAST_RADIUS,
                                               TaskState.PLAN_REVIEW, TaskState.AWAITING_APPROVAL),
                               approval_request=ApprovalRequest(task.task_id, task.revision, PlanDigest("current"), "req"))
        receipt = ApprovalReceipt("req", task.task_id, task.revision, PlanDigest("stale"), task.task.requester, True)
        with self.assertRaises(TransitionError):
            record_approval(task, receipt)

    def test_implementation_fix_returns_to_implementation(self):
        task = new_task("task-4", "Fix issue", RequesterIdentity("u"))
        task = TaskStateRecord(task.task, TaskState.VERIFYING, task.revision,
                               task.history + (TaskState.ANALYZE, TaskState.PLAN, TaskState.BLAST_RADIUS,
                                               TaskState.PLAN_REVIEW, TaskState.AWAITING_APPROVAL, TaskState.APPROVED,
                                               TaskState.IMPLEMENTING, TaskState.VERIFYING),
                               verification=(VerificationResult("AC", (Evidence("v", "failed", False),), False),))
        updated = transition(task, Event.IMPLEMENTATION_FIX_REQUIRED,
                             ResultReview(ReviewVerdict.IMPLEMENT_FIX, ("repair defect",)))
        self.assertEqual(updated.state, TaskState.IMPLEMENTING)
        self.assertEqual(updated.verification, ())

    def test_plan_revision_requires_plan_stage(self):
        task = new_task("task-5", "Fix issue", RequesterIdentity("u"))
        with self.assertRaises(TransitionError):
            revise_plan(task, Plan("Fix issue", (), (), ()))

    def test_first_plan_sets_revision_and_digest(self):
        task = new_task("first", "Feature", RequesterIdentity("u"))
        task = TaskStateRecord(task.task, TaskState.PLAN, task.revision, task.history + (TaskState.ANALYZE, TaskState.PLAN),
                               inspection=InspectionEvidenceRef("inspect-1", "baseline snapshot"))
        plan = Plan("Feature", (NormalizedOperation(OperationKind.WRITE, "a"),), (AcceptanceCriterion("c", "works", "test"),), ("test",))
        result = transition(task, Event.PLAN_RECORDED, plan)
        self.assertEqual(result.revision, 1)
        self.assertEqual(result.plan_digest, canonical_plan_digest(plan))

    def test_plan_recording_requires_nonempty_inspection_reference(self):
        task = new_task("first", "Feature", RequesterIdentity("u"))
        task = TaskStateRecord(task.task, TaskState.PLAN, task.revision, task.history + (TaskState.ANALYZE, TaskState.PLAN))
        plan = Plan("Feature", (NormalizedOperation(OperationKind.WRITE, "a"),), (AcceptanceCriterion("c", "works", "test"),), ("test",))
        with self.assertRaises(TransitionError):
            transition(task, Event.PLAN_RECORDED, plan)

    def test_malformed_inspection_reference_cannot_authorize_plan(self):
        plan = Plan("Feature", (NormalizedOperation(OperationKind.WRITE, "a"),), (AcceptanceCriterion("c", "works", "test"),), ("test",))
        for inspection in (InspectionEvidenceRef(" ", "baseline"), InspectionEvidenceRef("inspect-1", " ")):
            with self.subTest(inspection=inspection):
                task = new_task("first", "Feature", RequesterIdentity("u"))
                task = TaskStateRecord(task.task, TaskState.PLAN, task.revision, task.history + (TaskState.ANALYZE, TaskState.PLAN),
                                       inspection=inspection)
                with self.assertRaises(TransitionError):
                    transition(task, Event.PLAN_RECORDED, plan)

    def test_plan_review_wrong_verdicts_are_rejected(self):
        task = new_task("review", "Feature", RequesterIdentity("u"))
        task = TaskStateRecord(task.task, TaskState.PLAN_REVIEW, task.revision, task.history + (TaskState.PLAN_REVIEW,))
        for event, verdict in ((Event.PLAN_REVIEW_FAILED, ReviewVerdict.PASS), (Event.PLAN_REVIEW_PASSED, ReviewVerdict.NEEDS_CHANGES)):
            with self.assertRaises(TransitionError): transition(task, event, PlanReview(verdict))

    def test_event_verdict_bindings_are_enforced(self):
        task = TaskStateRecord(new_task("v", "x", RequesterIdentity("u")).task, TaskState.VERIFYING, 1, (TaskState.VERIFYING,))
        for event, verdict in ((Event.IMPLEMENTATION_FIX_REQUIRED, ReviewVerdict.PASS), (Event.REPLAN_REQUIRED, ReviewVerdict.IMPLEMENT_FIX), (Event.RESULT_REVIEW_PASSED, ReviewVerdict.REPLAN)):
            with self.assertRaises(TransitionError): transition(task, event, ResultReview(verdict))

    def test_result_review_requires_all_passed_evidence(self):
        plan = Plan("x", (NormalizedOperation(OperationKind.READ, "a"),), (AcceptanceCriterion("c", "works", "test"), AcceptanceCriterion("d", "safe", "audit")), ("test",))
        task = TaskStateRecord(new_task("e", "x", RequesterIdentity("u")).task, TaskState.VERIFYING, 1, (TaskState.VERIFYING,), plan=plan)
        for results in ((), (VerificationResult("c", (Evidence("ev", "claim", True),), True),), (VerificationResult("c", (Evidence("ev", "failed", False),), False), VerificationResult("d", (Evidence("ev2", "ok", True),), True)), (VerificationResult("c", (), True), VerificationResult("d", (Evidence("d", "ok", True),), True))):
            task = TaskStateRecord(task.task, task.state, task.revision, task.history, plan=plan, verification=results)
            with self.assertRaises(TransitionError): transition(task, Event.RESULT_REVIEW_PASSED, ResultReview(ReviewVerdict.PASS))

    def test_verification_requires_evidence_for_current_unique_criteria(self):
        plan = Plan("x", (NormalizedOperation(OperationKind.READ, "a"),), (AcceptanceCriterion("c", "works", "test"),), ("test",))
        task = TaskStateRecord(new_task("e2", "x", RequesterIdentity("u")).task, TaskState.IMPLEMENTING, 1, (TaskState.IMPLEMENTING,), plan=plan)
        for results in ((VerificationResult("other", (Evidence("e", "x"),), True),), (VerificationResult("c", (), True),), (VerificationResult("c", (Evidence("e", "x"),), True), VerificationResult("c", (Evidence("e2", "y"),), True))):
            with self.assertRaises(TransitionError): transition(task, Event.VERIFICATION_RECORDED, results)

    def test_handoff_requires_evidence(self):
        task = TaskStateRecord(new_task("h", "x", RequesterIdentity("u")).task, TaskState.HANDOFF, 1, (TaskState.HANDOFF,))
        with self.assertRaises(TransitionError): transition(task, Event.HANDOFF_RECORDED, Handoff("done", ()))

    def test_plan_edit_requires_existing_plan_in_plan_stage(self):
        task = new_task("edit", "x", RequesterIdentity("u"))
        task = TaskStateRecord(task.task, TaskState.PLAN, task.revision, task.history + (TaskState.PLAN,))
        with self.assertRaises(TransitionError): revise_plan(task, Plan("x", (), (), ()))

    def test_permit_rejects_wrong_digest_and_unplanned_scope(self):
        operation = NormalizedOperation(OperationKind.WRITE, "allowed")
        plan = Plan("x", (operation,), (AcceptanceCriterion("c", "works", "test"),), ("test",))
        digest = canonical_plan_digest(plan)
        task = new_task("permit", "x", RequesterIdentity("u"))
        receipt = ApprovalReceipt("r", task.task_id, 1, digest, task.task.requester, True)
        task = TaskStateRecord(task.task, TaskState.APPROVED, 1, (TaskState.APPROVED,), plan=plan, plan_digest=digest, approval=receipt)
        invalid = (ExecutionPermit(task.task_id, 1, PlanDigest("wrong"), MutationScope((operation,))),
                   ExecutionPermit(task.task_id, 1, digest, MutationScope((NormalizedOperation(OperationKind.DELETE, "other"),))))
        for permit in invalid:
            with self.assertRaises(TransitionError): transition(task, Event.IMPLEMENTATION_STARTED, permit)

    def test_plan_review_failure_requires_non_approved_verdict(self):
        task = new_task("task-r", "Change", RequesterIdentity("u"))
        task = TaskStateRecord(task.task, TaskState.PLAN_REVIEW, task.revision,
                               task.history + (TaskState.ANALYZE, TaskState.PLAN, TaskState.BLAST_RADIUS, TaskState.PLAN_REVIEW))
        with self.assertRaises(TransitionError):
            transition(task, Event.PLAN_REVIEW_FAILED, PlanReview(ReviewVerdict.APPROVED))

    def test_plan_revision_clears_exact_dependent_authorizations(self):
        task = new_task("task-1", "Add a feature", RequesterIdentity("user-1"))
        op = NormalizedOperation(OperationKind.WRITE, "src/a.py")
        plan = Plan("Add a feature", (op,), (), ("run tests",))
        criterion_plan = Plan("Add a feature", (op,),
                              (AcceptanceCriterion("AC1", "Works", "run"),),
                              ("run tests",))
        receipt = ApprovalReceipt("r1", task.task_id, task.revision, PlanDigest("d1"), task.task.requester, True)
        task = TaskStateRecord(task.task, TaskState.PLAN, task.revision,
                               task.history + (TaskState.ANALYZE, TaskState.PLAN),
                               inspection=InspectionEvidenceRef("e1", "baseline"),
                               analysis=Evidence("e2", "analysis"), plan=criterion_plan,
                               blast_radius=Evidence("e3", "impact"),
                               plan_review=PlanReview(ReviewVerdict.APPROVED),
                               approval_request=ApprovalRequest(task.task_id, task.revision, PlanDigest("d1"), "r1"),
                               approval=receipt,
                               permit=ExecutionPermit(task.task_id, task.revision, PlanDigest("d1"), MutationScope((op,))),
                               evidence=(Evidence("still-valid", "audit"),))
        revised = revise_plan(task, plan)
        self.assertEqual(revised.revision, 1)
        self.assertIsNone(revised.plan_review)
        self.assertIsNone(revised.approval_request)
        self.assertIsNone(revised.approval)
        self.assertIsNone(revised.permit)
        self.assertIsNone(revised.blast_radius)
        self.assertEqual(revised.inspection, task.inspection)
        self.assertEqual(revised.analysis, task.analysis)
        self.assertEqual(revised.evidence, task.evidence)

    def test_skipped_stage_is_rejected(self):
        task = new_task("task-1", "Add a feature", RequesterIdentity("user-1"))
        with self.assertRaises(TransitionError):
            transition(task, Event.PLAN_RECORDED, Plan("Add", (), (), ()))

    def test_plan_review_failure_returns_to_plan_and_clears_approval(self):
        task = new_task("task-1", "Add a feature", RequesterIdentity("user-1"))
        task = TaskStateRecord(task.task, TaskState.PLAN_REVIEW, task.revision,
                               task.history + (TaskState.ANALYZE, TaskState.PLAN, TaskState.BLAST_RADIUS, TaskState.PLAN_REVIEW),
                               plan_review=PlanReview(ReviewVerdict.REJECTED),
                               approval_request=ApprovalRequest(task.task_id, task.revision, PlanDigest("old"), "r1"))
        updated = transition(task, Event.PLAN_REVIEW_FAILED, task.plan_review)
        self.assertEqual(updated.state, TaskState.PLAN)
        self.assertIsNone(updated.approval_request)
        self.assertIsNone(updated.approval)
        self.assertIsNone(updated.permit)

    def test_replan_required_invalidates_existing_authorization(self):
        op = NormalizedOperation(OperationKind.WRITE, "src/a.py")
        plan = Plan("x", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",))
        digest = canonical_plan_digest(plan)
        base = new_task("replan", "x", RequesterIdentity("u"))
        request = ApprovalRequest(base.task_id, PlanRevision(1), digest, "req")
        receipt = ApprovalReceipt("req", base.task_id, PlanRevision(1), digest, base.task.requester, True)
        permit = ExecutionPermit(base.task_id, PlanRevision(1), digest, MutationScope((op,)))
        task = TaskStateRecord(
            base.task, TaskState.VERIFYING, PlanRevision(1), (TaskState.VERIFYING,),
            plan=plan, plan_digest=digest, blast_radius=Evidence("br", "impact"),
            plan_review=PlanReview(ReviewVerdict.APPROVED), approval_request=request,
            approval=receipt, permit=permit,
            verification=(VerificationResult("c", (Evidence("check", "result", True),), False),),
        )
        revised = transition(task, Event.REPLAN_REQUIRED, ResultReview(ReviewVerdict.REPLAN))
        self.assertEqual(revised.state, TaskState.PLAN)
        self.assertIsNone(revised.blast_radius)
        self.assertIsNone(revised.plan_review)
        self.assertIsNone(revised.approval_request)
        self.assertIsNone(revised.approval)
        self.assertIsNone(revised.permit)

    def test_verification_requires_all_criteria_at_stage_entry(self):
        plan = Plan("x", (NormalizedOperation(OperationKind.READ, "a"),),
                    (AcceptanceCriterion("c", "works", "test"), AcceptanceCriterion("d", "safe", "audit")),
                    ("test",))
        task = TaskStateRecord(new_task("complete-verification", "x", RequesterIdentity("u")).task,
                               TaskState.IMPLEMENTING, PlanRevision(1), (TaskState.IMPLEMENTING,), plan=plan)
        partial = (VerificationResult("c", (Evidence("ev", "actual test output", True),), True),)
        with self.assertRaises(TransitionError):
            transition(task, Event.VERIFICATION_RECORDED, partial)

    def test_result_review_rejects_failed_evidence_claimed_as_passed(self):
        plan = Plan("x", (NormalizedOperation(OperationKind.READ, "a"),),
                    (AcceptanceCriterion("c", "works", "test"),), ("test",))
        task = TaskStateRecord(new_task("contradictory-evidence", "x", RequesterIdentity("u")).task,
                               TaskState.VERIFYING, PlanRevision(1), (TaskState.VERIFYING,), plan=plan,
                               verification=(VerificationResult("c", (Evidence("ev", "failed test output", False),), True),))
        with self.assertRaises(TransitionError):
            transition(task, Event.RESULT_REVIEW_PASSED, ResultReview(ReviewVerdict.PASS))

    def test_plan_review_failure_preserves_findings_and_invalidates_impact(self):
        task = new_task("failed-review", "x", RequesterIdentity("u"))
        review_task = TaskStateRecord(
            task.task, TaskState.PLAN_REVIEW, PlanRevision(1), (TaskState.PLAN_REVIEW,),
            plan=Plan("x", (NormalizedOperation(OperationKind.READ, "a"),),
                      (AcceptanceCriterion("c", "works", "test"),), ("test",)),
            plan_digest=PlanDigest("d"), blast_radius=Evidence("br", "impact"),
        )
        review = PlanReview(ReviewVerdict.NEEDS_CHANGES, ("include error handling",))
        result = transition(review_task, Event.PLAN_REVIEW_FAILED, review)
        self.assertEqual(result.state, TaskState.PLAN)
        self.assertEqual(result.plan_review, review)
        self.assertIsNone(result.blast_radius)

    def test_implementation_fix_preserves_review_findings(self):
        task = new_task("fix-findings", "x", RequesterIdentity("u"))
        fix_task = TaskStateRecord(
            task.task, TaskState.VERIFYING, PlanRevision(1), (TaskState.VERIFYING,),
            verification=(VerificationResult("c", (Evidence("ev", "failed", False),), False),),
        )
        review = ResultReview(ReviewVerdict.IMPLEMENT_FIX, ("handle empty input",))
        result = transition(fix_task, Event.IMPLEMENTATION_FIX_REQUIRED, review)
        self.assertEqual(result.state, TaskState.IMPLEMENTING)
        self.assertEqual(result.result_review, review)
        self.assertEqual(result.verification, ())

    def test_terminal_task_cannot_transition_again(self):
        task = new_task("task-1", "Add a feature", RequesterIdentity("user-1"))
        task = transition(task, Event.CANCEL)
        with self.assertRaises(TransitionError):
            transition(task, Event.FAIL)


if __name__ == "__main__":
    unittest.main()
