"""Offline artifact integrity, never a physical acceptance certificate."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/verify-split-evidence-artifacts.py"
spec = importlib.util.spec_from_file_location("split_artifact_checker", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@unittest.skipUnless(all(hasattr(os, n) for n in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")),
                     "requires Linux/macOS safe file APIs")
class SplitEvidenceArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "artifacts"
        self.evidence.mkdir()
        self.report = module.schema.template("a" * 40, "18.1.2", "iPhone13,4", "2026-11-25T00:00:00Z")
        self.case = "wifi_system_dns"
        self.path = self.evidence / (self.case + ".txt")
        self.data = b"synthetic redacted observation"
        self.report["signed_device"] = True
        self.report["cases"][self.case] = {
            "status": "pass", "evidence_sha256": hashlib.sha256(self.data).hexdigest()
        }

    def test_match_and_partial_report(self):
        self.path.write_bytes(self.data)
        counts, checked = module.verify(self.report, self.evidence)
        self.assertEqual(checked, 1)
        self.assertEqual(counts["not_run"], len(module.schema.CASES) - 1)
        report_path = self.root / "report.json"
        report_path.write_text(json.dumps(self.report), encoding="utf-8")
        args = [sys.executable, str(SCRIPT), str(report_path), str(self.evidence)]
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Human review", result.stdout)
        self.assertEqual(subprocess.run(args + ["--require-complete"],
                                        capture_output=True).returncode, 1)

    def test_missing_and_mismatched_artifact(self):
        with self.assertRaises(module.schema.InvalidReport):
            module.verify(self.report, self.evidence)
        self.path.write_bytes(b"tampered do-not-echo")
        with self.assertRaises(module.schema.InvalidReport) as error:
            module.verify(self.report, self.evidence)
        self.assertNotIn("do-not-echo", str(error.exception))

    def test_symlinks_and_nonregular_files_rejected(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(self.data)
        self.path.symlink_to(outside)
        with self.assertRaises(module.schema.InvalidReport):
            module.verify(self.report, self.evidence)
        self.path.unlink()
        os.mkfifo(self.path)
        with self.assertRaises(module.schema.InvalidReport):
            module.verify(self.report, self.evidence)
        self.path.unlink()
        self.path.write_bytes(self.data)
        linked_root = self.root / "linked"
        linked_root.symlink_to(self.evidence, target_is_directory=True)
        with self.assertRaises(module.schema.InvalidReport):
            module.verify(self.report, linked_root)

    def test_empty_and_oversized_artifacts(self):
        for data in (b"", b"x" * (module.MAX_ARTIFACT_BYTES + 1)):
            self.path.write_bytes(data)
            self.report["cases"][self.case]["evidence_sha256"] = hashlib.sha256(data).hexdigest()
            with self.assertRaises(module.schema.InvalidReport):
                module.verify(self.report, self.evidence)

    def test_fail_case_is_checked_and_not_run_is_not_read(self):
        self.report["cases"][self.case]["status"] = "fail"
        self.path.write_bytes(self.data)
        (self.evidence / "cellular_system_dns.txt").symlink_to(self.root / "nonexistent")
        counts, checked = module.verify(self.report, self.evidence)
        self.assertEqual(counts["fail"], 1)
        self.assertEqual(checked, 1)


if __name__ == "__main__":
    unittest.main()
