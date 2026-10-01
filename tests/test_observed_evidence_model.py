import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engineering-gate"))

from engineering_gate_core.models import ObservedCommandEvidence, EvidenceProvenance, WorkspaceIdentity, _ISSUER


class ObservedEvidenceModelTests(unittest.TestCase):
    def test_public_constructor_rejects_direct_observation_creation(self):
        with self.assertRaisesRegex(ValueError, "issued by the gate"):
            ObservedCommandEvidence(
                task_id="task-1", plan_revision=1, plan_digest="a" * 64,
                criterion_id="c1", provenance=EvidenceProvenance.GATE_OBSERVED,
                argv=("pytest",), workspace_identity=WorkspaceIdentity("/tmp", 1, 2),
                started_at="2026-01-01T00:00:00Z", completed_at="2026-01-01T00:00:01Z",
                exit_code=0, stdout_digest="b" * 64, stderr_digest="c" * 64,
                output_summary="ok", timed_out=False,
            )

    def test_internal_issue_and_restore_validate_observed_evidence(self):
        values = dict(task_id="task-1", plan_revision=1, plan_digest="a" * 64,
                      criterion_id="c1", argv=("pytest",), workspace_identity=WorkspaceIdentity("/tmp", 1, 2),
                      started_at="2026-01-01T00:00:00Z", completed_at="2026-01-01T00:00:01Z",
                      exit_code=0, stdout_digest="b" * 64, stderr_digest="c" * 64,
                      output_summary="ok", timed_out=False)
        with self.assertRaisesRegex(ValueError, "issued by the gate"):
            ObservedCommandEvidence._issue(**values)
        with self.assertRaisesRegex(ValueError, "issued by the gate"):
            ObservedCommandEvidence._issue(_issuer=object(), **values)
        self.assertEqual(ObservedCommandEvidence._issue(_issuer=_ISSUER, **values).provenance, EvidenceProvenance.GATE_OBSERVED)
        self.assertEqual(ObservedCommandEvidence._restore(**values).output_summary, "ok")
        for summary in (None, "x" * 513):
            with self.assertRaises(ValueError):
                ObservedCommandEvidence._restore(**{**values, "output_summary": summary})


if __name__ == "__main__":
    unittest.main()
