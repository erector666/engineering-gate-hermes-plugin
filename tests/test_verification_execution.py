import hashlib
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1] / "engineering-gate"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engineering_gate_core.models import ObservedCommandEvidence, VerificationCommand, WorkspaceIdentity
from engineering_gate_core.verification_execution import (
    CommandLaunchError,
    _observe_verification_command,
)


class VerificationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.stat = self.root.stat()
        self.identity = WorkspaceIdentity(str(self.root), self.stat.st_dev, self.stat.st_ino)

    def tearDown(self):
        self.temp.cleanup()

    def command(self, code, timeout=3, cap=256, executable=None):
        return VerificationCommand((executable or sys.executable, "-c", code), ("criterion-1",), timeout, cap)

    def observe(self, command, identity=None):
        return _observe_verification_command(
            command, task_id="task-1", plan_revision=2, plan_digest="a" * 64,
            criterion_id="criterion-1", workspace_identity=identity or self.identity,
        )

    def test_exit_zero_passes(self):
        result = self.observe(self.command("print('ok')"))
        self.assertTrue(result.passed)
        self.assertEqual(result.exit_code, 0)

    def test_exit_one_fails_even_when_stdout_says_pass(self):
        result = self.observe(self.command("print('PASS'); raise SystemExit(1)"))
        self.assertFalse(result.passed)
        self.assertEqual(result.exit_code, 1)

    def test_large_streams_are_bounded_but_fully_hashed(self):
        stdout = b"o" * 500_000
        stderr = b"e" * 450_000
        code = "import sys; sys.stdout.write('o'*500000); sys.stderr.write('e'*450000)"
        result = self.observe(self.command(code, cap=128))
        self.assertEqual(result.stdout_digest, hashlib.sha256(stdout).hexdigest())
        self.assertEqual(result.stderr_digest, hashlib.sha256(stderr).hexdigest())
        self.assertLessEqual(len(result.output_summary.encode()), 512)

    def test_timeout_fails_closed(self):
        result = self.observe(self.command("import time; time.sleep(5)", timeout=1))
        self.assertTrue(result.timed_out)
        self.assertFalse(result.passed)

    def test_escaped_descendant_retaining_pipes_fails_within_bounded_drain(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("escaped session descendant regression requires Linux")
        marker = self.root / "escaped-helper.pid"
        helper = (
            "import os,time; os.setsid(); "
            f"open({str(marker)!r}, 'w').write(str(os.getpid())); "
            "time.sleep(30)"
        )
        parent = (
            "import subprocess,sys; "
            f"subprocess.Popen([sys.executable, '-c', {helper!r}])"
        )
        started = time.monotonic()
        try:
            result = self.observe(self.command(parent, timeout=1))
            self.assertFalse(result.passed)
            self.fail("escaped descendant must prevent complete output evidence")
        except Exception as exc:
            from engineering_gate_core.verification_execution import OutputIncompleteError
            self.assertIsInstance(exc, OutputIncompleteError)
            self.assertEqual(exc.returncode, 0)
        finally:
            self.assertLess(time.monotonic() - started, 4)
            if marker.exists():
                pid = int(marker.read_text())
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.02)

    def test_timeout_terminates_pipe_inheriting_child_promptly(self):
        if os.name != "posix":
            self.skipTest("process-group termination guarantee is POSIX-specific")
        import time
        code = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); time.sleep(30)"
        started = time.monotonic()
        result = self.observe(self.command(code, timeout=1))
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 4)

    def test_observed_evidence_cannot_be_constructed_directly(self):
        with self.assertRaises(ValueError):
            ObservedCommandEvidence(
                task_id="task-1", plan_revision=2, plan_digest="a" * 64,
                criterion_id="criterion-1", provenance="gate_observed", argv=(sys.executable,),
                workspace_identity=self.identity, started_at="2026-01-01T00:00:00Z",
                completed_at="2026-01-01T00:00:01Z", exit_code=0,
                stdout_digest="b" * 64, stderr_digest="c" * 64,
                output_summary="", timed_out=False,
            )

    def test_launch_failure_raises_typed_error(self):
        with self.assertRaises(CommandLaunchError):
            self.observe(self.command("pass", executable="/no/such/approved-executable"))

    def test_workspace_replacement_before_spawn_uses_pinned_original_directory(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("pinned cwd regression requires Linux /proc/self/fd")
        from engineering_gate_core import verification_execution

        moved = self.root.with_name(self.root.name + "-moved")
        report = self.root.parent / (self.root.name + "-report")
        (self.root / "marker").write_text("original")
        replacement = None
        real_popen = verification_execution.subprocess.Popen

        def replace_then_spawn(*args, **kwargs):
            nonlocal replacement
            self.root.rename(moved)
            replacement = self.root
            replacement.mkdir()
            (replacement / "marker").write_text("replacement")
            return real_popen(*args, **kwargs)

        code = ("from pathlib import Path; "
                f"Path({str(report)!r}).write_text(Path('marker').read_text())")
        try:
            with patch.object(verification_execution.subprocess, "Popen", side_effect=replace_then_spawn):
                with self.assertRaises(verification_execution.WorkspaceIdentityError):
                    self.observe(self.command(code))
            self.assertTrue(report.exists(), "the real child should have run")
            self.assertEqual(report.read_text(), "original")
            self.assertEqual((replacement / "marker").read_text(), "replacement")
        finally:
            if report.exists():
                report.unlink()
            if replacement is not None and replacement.exists():
                import shutil
                shutil.rmtree(replacement)
            if moved.exists():
                import shutil
                shutil.rmtree(moved)

    def test_replaced_workspace_identity_fails_closed(self):
        moved = self.root.with_name(self.root.name + "-moved")
        self.root.rename(moved)
        self.root.mkdir()
        with self.assertRaises((OSError, RuntimeError)):
            self.observe(self.command("pass"))

    def test_summary_redacts_token_like_secrets(self):
        raw = "api_key=example-placeholder-12345"
        result = self.observe(self.command(f"print({raw!r})"))
        self.assertNotIn(raw, result.output_summary)
        self.assertIn("api_key=[REDACTED]", result.output_summary)


if __name__ == "__main__":
    unittest.main()
