import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.models import (AcceptanceCriterion, ApprovalReceipt, ApprovalRequest, Evidence, ExecutionPermit, Handoff, InspectionEvidenceRef, MutationAuthorization, MutationProposal, MutationScope, NormalizedOperation, OperationKind, Plan, PlanDigest, PlanReview, PlanRevision, RequesterIdentity, ResultReview, ReviewVerdict, TaskState, TaskStateRecord, VerificationResult, VerificationCommand, WorkspaceIdentity, ObservedCommandEvidence, _ISSUER)
from engineering_gate_core.workflow import Stage, new_task, transition, Event, TransitionError, record_approval, revise_plan, canonical_plan_digest, canonical_mutation_proposal_digest, mutation_argument_digest, record_mutation_proposal, record_mutation_authorization, capture_workspace_identity, resolve_approved_verification_commands


class WorkflowTests(unittest.TestCase):
    def observed(self, criterion="c", passed=True):
        from hashlib import sha256
        return ObservedCommandEvidence._issue(
            _issuer=_ISSUER, task_id="test-task", plan_revision=1, plan_digest="0" * 64,
            criterion_id=criterion, argv=("test-command",),
            workspace_identity=WorkspaceIdentity("/test-only", 1, 1),
            started_at="2026-10-01T10:00:00Z", completed_at="2026-10-01T10:00:01Z",
            exit_code=0 if passed else 1, stdout_digest=sha256(b"out").hexdigest(),
            stderr_digest=sha256(b"").hexdigest(), output_summary="test-only", timed_out=False)

    def test_verification_command_fields_are_bound_to_plan_digest(self):
        command = VerificationCommand(("pytest", "tests/test_x.py"), ("c",), 30, 4096)
        plan = Plan("x", (), (AcceptanceCriterion("c", "works", "run"), AcceptanceCriterion("other", "other", "run")), (), verification_commands=(command,))
        digest = canonical_plan_digest(plan)
        for changed in (__import__("dataclasses").replace(command, argv=("pytest", "-q")),
                        __import__("dataclasses").replace(command, criterion_ids=("other",)),
                        __import__("dataclasses").replace(command, timeout_seconds=31),
                        __import__("dataclasses").replace(command, output_cap_bytes=4097)):
            self.assertNotEqual(digest, canonical_plan_digest(__import__("dataclasses").replace(plan, verification_commands=(changed,))))

    def test_verification_command_rejects_shell_strings_and_bad_criterion_mapping(self):
        for argv in ("pytest -q", (), ("pytest", ""), ("pytest", 3)):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                VerificationCommand(argv, ("c",), 30, 4096)
        with self.assertRaises(ValueError):
            Plan("x", (), (AcceptanceCriterion("c", "works", "run"),), (),
                 verification_commands=(VerificationCommand(("pytest",), ("missing",), 30, 4096),))

    def test_resolver_returns_only_commands_for_current_criterion(self):
        commands = (VerificationCommand(("pytest", "a"), ("a",), 30, 4096),
                    VerificationCommand(("pytest", "b"), ("b",), 30, 4096))
        plan = Plan("x", (), (AcceptanceCriterion("a", "A", "run"), AcceptanceCriterion("b", "B", "run")), (), verification_commands=commands)
        self.assertEqual(resolve_approved_verification_commands(plan, ("a",)), (commands[0],))
        with self.assertRaises(TransitionError):
            resolve_approved_verification_commands(plan, ("missing",))

    def test_mutation_proposal_and_authorization_bind_to_live_implementing_plan(self):
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "update output")
        import tempfile
        with tempfile.TemporaryDirectory() as workspace:
            root = str(Path(workspace).resolve())
            plan = Plan("change", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",), workspace_root=root,
                        workspace_identity=__import__("engineering_gate_core.workflow", fromlist=["capture_workspace_identity"]).capture_workspace_identity(root))
            digest = canonical_plan_digest(plan)
            base = new_task("proposal-task", "change", RequesterIdentity("u"))
            task = TaskStateRecord(base.task, TaskState.IMPLEMENTING, PlanRevision(1), (TaskState.IMPLEMENTING,),
                                   plan=plan, plan_digest=digest, plan_review=PlanReview(ReviewVerdict.APPROVED),
                                   approval_request=ApprovalRequest(base.task_id, PlanRevision(1), digest, "request"),
                                   approval=ApprovalReceipt("request", base.task_id, PlanRevision(1), digest, base.task.requester, True),
                                   permit=ExecutionPermit(base.task_id, PlanRevision(1), digest, MutationScope((op,))))
            proposal = MutationProposal("p1", task.task_id, task.revision, digest, op, mutation_argument_digest("hello"), "write reviewed output")
            recorded = record_mutation_proposal(task, proposal)
            auth = MutationAuthorization("a1", task.task_id, task.revision, digest,
                                         canonical_mutation_proposal_digest(proposal), "provider",
                                         "2026-10-01T10:00:00Z", "2026-10-01T11:00:00Z")
            with self.assertRaises(TransitionError):
                record_mutation_authorization(recorded, auth, now="2026-10-01T10:30:00Z")
            # Legacy decoded claims are data only and cannot establish authority.
            authorized = __import__("dataclasses").replace(recorded, mutation_authorization=auth)
            changed = MutationProposal("p2", task.task_id, task.revision, digest, op, mutation_argument_digest("different"), "write reviewed output")
            self.assertIsNone(record_mutation_proposal(authorized, changed).mutation_authorization)

    def test_mutation_proposal_rejects_unapproved_or_mismatched_plan_binding(self):
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "update output")
        plan = Plan("change", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",))
        base = new_task("proposal-invalid", "change", RequesterIdentity("u"))
        task = TaskStateRecord(base.task, TaskState.IMPLEMENTING, PlanRevision(1), (TaskState.IMPLEMENTING,),
                               plan=plan, plan_digest=canonical_plan_digest(plan),
                               plan_review=PlanReview(ReviewVerdict.APPROVED))
        proposal = MutationProposal("p", task.task_id, task.revision, task.plan_digest, op,
                                    mutation_argument_digest("x"), "write")
        with self.assertRaises(TransitionError):
            record_mutation_proposal(task, proposal)

    def test_mutation_proposal_requires_current_plan_and_approval_bindings(self):
        import tempfile
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "update")
        with tempfile.TemporaryDirectory() as workspace:
            root = str(Path(workspace).resolve())
            plan = Plan("change", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",),
                        workspace_root=root, workspace_identity=capture_workspace_identity(root))
            base = new_task("binding", "change", RequesterIdentity("u"))
            digest = canonical_plan_digest(plan)
            current = TaskStateRecord(base.task, TaskState.IMPLEMENTING, PlanRevision(1),
                (TaskState.IMPLEMENTING,), plan=plan, plan_digest=digest,
                plan_review=PlanReview(ReviewVerdict.APPROVED),
                approval_request=ApprovalRequest(base.task_id, 1, digest, "request"),
                approval=ApprovalReceipt("request", base.task_id, 1, digest, base.task.requester, True),
                permit=ExecutionPermit(base.task_id, 1, digest, MutationScope((op,))))
            proposal = MutationProposal("p", base.task_id, 1, digest, op, mutation_argument_digest("x"), "write")
            stale_task = MutationProposal("p", "another-task", 1, digest, op, mutation_argument_digest("x"), "write")
            stale_revision = MutationProposal("p", base.task_id, 2, digest, op, mutation_argument_digest("x"), "write")
            stale_plan = MutationProposal("p", base.task_id, 1, PlanDigest("0" * 64), op, mutation_argument_digest("x"), "write")
            for invalid in (
                __import__("dataclasses").replace(current, task=__import__("dataclasses").replace(current.task, task_id="other")),
                __import__("dataclasses").replace(current, plan_digest=PlanDigest("0" * 64)),
                __import__("dataclasses").replace(current, approval=ApprovalReceipt("wrong", base.task_id, 1, digest, base.task.requester, True)),
                __import__("dataclasses").replace(current, permit=ExecutionPermit(base.task_id, 1, digest, MutationScope(()))),
                __import__("dataclasses").replace(current, plan=__import__("dataclasses").replace(plan, workspace_identity=None)),
            ):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(TransitionError): record_mutation_proposal(invalid, proposal)
            for invalid_proposal in (stale_task, stale_revision, stale_plan,
                                     __import__("dataclasses").replace(proposal, operation=NormalizedOperation(OperationKind.WRITE, "other", "write"))):
                with self.subTest(invalid_proposal=invalid_proposal):
                    with self.assertRaises(TransitionError): record_mutation_proposal(current, invalid_proposal)
            with self.assertRaises(ValueError):
                __import__("dataclasses").replace(proposal,
                    operation=NormalizedOperation(OperationKind.PATCH, "output.txt", "patch"))

    def test_mutation_proposal_rejects_noncanonical_argument_digest(self):
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "update")
        base = new_task("bad-digest", "change", RequesterIdentity("u"))
        with self.assertRaises(ValueError):
            MutationProposal("p", base.task_id, 1, PlanDigest("0" * 64), op, "not-a-digest", "write")

    def test_mutation_authorization_rejects_noncanonical_timestamp(self):
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "update")
        base = new_task("bad-time", "change", RequesterIdentity("u"))
        with self.assertRaises(ValueError):
            MutationAuthorization("a", base.task_id, 1, PlanDigest("0" * 64), "0" * 64,
                                  "provider", "2026-10-01T10:00:00+00:00", "2026-10-01T11:00:00Z")

    def test_mutation_argument_digest_is_exact_and_rejects_nonstring(self):
        import hashlib
        import json
        value = "é\n"
        expected = hashlib.sha256(json.dumps({"content": value}, sort_keys=True, separators=(",", ":"),
                                             ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()
        self.assertEqual(mutation_argument_digest(value), expected)
        for invalid in (None, 3, float("nan")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                mutation_argument_digest(invalid)

    def test_mutation_proposal_digest_tracks_every_bound_field(self):
        from dataclasses import replace
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "update")
        base = new_task("proposal-digest", "change", RequesterIdentity("u"))
        proposal = MutationProposal("p", base.task_id, 1, PlanDigest("0" * 64), op,
                                    mutation_argument_digest("x"), "write")
        digest = canonical_mutation_proposal_digest(proposal)
        for changed in (replace(proposal, proposal_id="p2"), replace(proposal, operation=replace(op, rationale="other")),
                        replace(proposal, argument_digest=mutation_argument_digest("y")),
                        replace(proposal, rationale="different"),
                        replace(proposal, diff_digest="1" * 64)):
            self.assertNotEqual(digest, canonical_mutation_proposal_digest(changed))

    def test_proposal_digest_is_instance_stable_and_argument_sensitive(self):
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "update")
        args = mutation_argument_digest("x")
        first = MutationProposal("p", "task", 1, PlanDigest("0" * 64), op, args, "write")
        second = MutationProposal("p", "task", 1, PlanDigest("0" * 64), op, args, "write")
        changed = MutationProposal("p", "task", 1, PlanDigest("0" * 64), op,
                                   mutation_argument_digest("y"), "write")
        self.assertEqual(canonical_mutation_proposal_digest(first), canonical_mutation_proposal_digest(second))
        self.assertNotEqual(canonical_mutation_proposal_digest(first), canonical_mutation_proposal_digest(changed))

    def test_mutation_authorization_expiry_is_exclusive(self):
        import tempfile
        from dataclasses import replace
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "update")
        base = new_task("expiry", "change", RequesterIdentity("u"))
        with tempfile.TemporaryDirectory() as workspace:
            root = str(Path(workspace).resolve())
            plan = Plan("change", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",),
                        workspace_root=root, workspace_identity=capture_workspace_identity(root))
            digest = canonical_plan_digest(plan)
            state = TaskStateRecord(base.task, TaskState.IMPLEMENTING, 1, (TaskState.IMPLEMENTING,), plan=plan,
                plan_digest=digest, plan_review=PlanReview(ReviewVerdict.APPROVED),
                approval_request=ApprovalRequest(base.task_id, 1, digest, "r"),
                approval=ApprovalReceipt("r", base.task_id, 1, digest, base.task.requester, True),
                permit=ExecutionPermit(base.task_id, 1, digest, MutationScope((op,))))
            proposal = MutationProposal("p", base.task_id, 1, digest, op, mutation_argument_digest("x"), "write")
            state = record_mutation_proposal(state, proposal)
            auth = MutationAuthorization("a", base.task_id, 1, digest, canonical_mutation_proposal_digest(proposal),
                                         "provider", "2026-10-01T10:00:00Z", "2026-10-01T11:00:00Z")
            with self.assertRaises(TransitionError):
                record_mutation_authorization(state, auth, now="2026-10-01T11:00:00Z")
            with self.assertRaises(TransitionError):
                record_mutation_authorization(replace(state, approval_request=None), auth, now="2026-10-01T10:30:00Z")
            for invalid_auth in (
                replace(auth, task_id="other"), replace(auth, revision=2),
                replace(auth, plan_digest=PlanDigest("0" * 64)),
                replace(auth, proposal_digest="0" * 64),
                replace(auth, expires_at="2026-10-01T10:30:00Z"),
                replace(auth, authorized_at="2026-10-01T10:31:00Z"),
            ):
                with self.subTest(invalid_auth=invalid_auth), self.assertRaises(TransitionError):
                    record_mutation_authorization(state, invalid_auth, now="2026-10-01T10:30:00Z")

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
    def test_caller_transition_cannot_record_verification(self):
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
        with self.assertRaises(TransitionError):
            transition(task, Event.VERIFICATION_RECORDED, ())

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
                               verification=(VerificationResult("AC", (self.observed("AC", False),)),))
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

    def test_plan_recording_captures_identity_instead_of_trusting_supplied_numbers(self):
        import tempfile
        with tempfile.TemporaryDirectory() as workspace:
            root = str(Path(workspace).resolve())
            task = new_task("identity", "Feature", RequesterIdentity("u"))
            task = TaskStateRecord(task.task, TaskState.PLAN, task.revision,
                                   task.history + (TaskState.ANALYZE, TaskState.PLAN),
                                   inspection=InspectionEvidenceRef("inspect-1", "baseline"))
            plan = Plan("Feature", (NormalizedOperation(OperationKind.WRITE, "a"),),
                        (AcceptanceCriterion("c", "works", "test"),), ("test",),
                        workspace_root=root,
                        workspace_identity=WorkspaceIdentity(root, -1, -1))
            recorded = transition(task, Event.PLAN_RECORDED, plan)
            actual = Path(root).stat()
            self.assertEqual(recorded.plan.workspace_identity,
                             WorkspaceIdentity(root, actual.st_dev, actual.st_ino))
            self.assertEqual(recorded.plan_digest, canonical_plan_digest(recorded.plan))

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
        for results in ((), (VerificationResult("c", (self.observed("c"),)),), (VerificationResult("c", (self.observed("c", False),)), VerificationResult("d", (self.observed("d"),))), (VerificationResult("c", (self.observed("c"),)), VerificationResult("d", (self.observed("d"),)))):
            task = TaskStateRecord(task.task, task.state, task.revision, task.history, plan=plan, verification=results)
            with self.assertRaises(TransitionError): transition(task, Event.RESULT_REVIEW_PASSED, ResultReview(ReviewVerdict.PASS))

    def test_verification_requires_evidence_for_current_unique_criteria(self):
        plan = Plan("x", (NormalizedOperation(OperationKind.READ, "a"),), (AcceptanceCriterion("c", "works", "test"),), ("test",))
        task = TaskStateRecord(new_task("e2", "x", RequesterIdentity("u")).task, TaskState.IMPLEMENTING, 1, (TaskState.IMPLEMENTING,), plan=plan)
        for results in ((VerificationResult("other", (self.observed("other"),)),), (VerificationResult("c", (self.observed("c"),)),), (VerificationResult("c", (self.observed("c"),)), VerificationResult("c", (self.observed("c"),)))):
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
            verification=(VerificationResult("c", (self.observed("c"),)),),
        )
        revised = transition(task, Event.REPLAN_REQUIRED, ResultReview(ReviewVerdict.REPLAN))
        self.assertEqual(revised.state, TaskState.PLAN)
        self.assertIsNone(revised.blast_radius)
        self.assertIsNone(revised.plan_review)
        self.assertIsNone(revised.approval_request)
        self.assertIsNone(revised.approval)
        self.assertIsNone(revised.permit)

    def test_proposal_and_authorization_are_cleared_by_all_plan_and_fix_invalidations(self):
        import tempfile
        op = NormalizedOperation(OperationKind.WRITE, "output.txt", "update")
        with tempfile.TemporaryDirectory() as workspace:
            root = str(Path(workspace).resolve())
            plan = Plan("x", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",),
                        workspace_root=root, workspace_identity=capture_workspace_identity(root))
            digest = canonical_plan_digest(plan)
            base = new_task("invalidate", "x", RequesterIdentity("u"))
            proposal = MutationProposal("p", base.task_id, 1, digest, op, mutation_argument_digest("x"), "write")
            auth = MutationAuthorization("a", base.task_id, 1, digest, canonical_mutation_proposal_digest(proposal),
                "provider", "2026-10-01T10:00:00Z", "2026-10-01T11:00:00Z")
            common = dict(plan=plan, plan_digest=digest, plan_review=PlanReview(ReviewVerdict.APPROVED),
                approval_request=ApprovalRequest(base.task_id, 1, digest, "r"),
                approval=ApprovalReceipt("r", base.task_id, 1, digest, base.task.requester, True),
                permit=ExecutionPermit(base.task_id, 1, digest, MutationScope((op,))),
                mutation_proposal=proposal, mutation_authorization=auth)
            plan_state = TaskStateRecord(base.task, TaskState.PLAN, 1, (TaskState.PLAN,), **common)
            new_plan = Plan("x2", (op,), (AcceptanceCriterion("c", "works", "test"),), ("test",),
                workspace_root=root, workspace_identity=capture_workspace_identity(root))
            revised = revise_plan(plan_state, new_plan)
            self.assertIsNone(revised.mutation_proposal)
            self.assertIsNone(revised.mutation_authorization)
            checks = (
                (TaskStateRecord(base.task, TaskState.VERIFYING, 1, (TaskState.VERIFYING,), **common,
                    verification=(VerificationResult("c", (self.observed("c", False),)),)),
                 Event.REPLAN_REQUIRED, ResultReview(ReviewVerdict.REPLAN)),
                (TaskStateRecord(base.task, TaskState.PLAN_REVIEW, 1, (TaskState.PLAN_REVIEW,), **common),
                 Event.PLAN_REVIEW_FAILED, PlanReview(ReviewVerdict.NEEDS_CHANGES)),
                (TaskStateRecord(base.task, TaskState.VERIFYING, 1, (TaskState.VERIFYING,), **common,
                    verification=(VerificationResult("c", (self.observed("c", False),)),)),
                 Event.IMPLEMENTATION_FIX_REQUIRED, ResultReview(ReviewVerdict.IMPLEMENT_FIX)),
            )
            for state, event, payload in checks:
                updated = transition(state, event, payload)
                with self.subTest(event=event):
                    self.assertIsNone(updated.mutation_proposal)
                    self.assertIsNone(updated.mutation_authorization)

    def test_verification_requires_all_criteria_at_stage_entry(self):
        plan = Plan("x", (NormalizedOperation(OperationKind.READ, "a"),),
                    (AcceptanceCriterion("c", "works", "test"), AcceptanceCriterion("d", "safe", "audit")),
                    ("test",))
        task = TaskStateRecord(new_task("complete-verification", "x", RequesterIdentity("u")).task,
                               TaskState.IMPLEMENTING, PlanRevision(1), (TaskState.IMPLEMENTING,), plan=plan)
        partial = (VerificationResult("c", (self.observed("c"),)),)
        with self.assertRaises(TransitionError):
            transition(task, Event.VERIFICATION_RECORDED, partial)

    def test_generic_passed_evidence_cannot_satisfy_verification(self):
        plan = Plan("x", (NormalizedOperation(OperationKind.READ, "a"),),
                    (AcceptanceCriterion("c", "works", "test"),), ("test",))
        task = TaskStateRecord(new_task("generic-claim", "x", RequesterIdentity("u")).task,
                               TaskState.IMPLEMENTING, 1, (TaskState.IMPLEMENTING,), plan=plan)
        with self.assertRaises(ValueError):
            VerificationResult("c", (Evidence("ev", "trust me", True),))
        with self.assertRaises(TransitionError):
            transition(task, Event.VERIFICATION_RECORDED, ())

    def test_result_review_rejects_failed_evidence_claimed_as_passed(self):
        plan = Plan("x", (NormalizedOperation(OperationKind.READ, "a"),),
                    (AcceptanceCriterion("c", "works", "test"),), ("test",))
        task = TaskStateRecord(new_task("contradictory-evidence", "x", RequesterIdentity("u")).task,
                               TaskState.VERIFYING, PlanRevision(1), (TaskState.VERIFYING,), plan=plan,
                               verification=(VerificationResult("c", (self.observed("c", False),)),))
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
            verification=(VerificationResult("c", (self.observed("c", False),)),),
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
