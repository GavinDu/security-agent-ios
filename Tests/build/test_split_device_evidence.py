"""The report schema cannot substitute for signed device observations."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/validate-split-device-evidence.py"
spec = importlib.util.spec_from_file_location("split_device_evidence", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SplitDeviceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.report = module.template("a" * 40, "18.1.2", "iPhone13,4", "2026-11-25T00:00:00Z")
        self.digest = hashlib.sha256(b"synthetic redacted test fixture").hexdigest()

    def test_template_never_claims_device_evidence(self):
        self.assertEqual(module.validate(self.report), {"fail": 0, "not_run": len(module.CASES), "pass": 0})
        self.assertFalse(self.report["signed_device"])
        self.assertEqual(len(module.CASES), len(set(module.CASES)))
        self.assertIn("nat64_no_outer_packetflow", module.CASES)
        self.assertIn("cellular_unsafe_mapped_aaaa", module.CASES)

    def test_rejects_missing_unknown_and_sensitive_fields(self):
        for mutate in (
            lambda x: x["cases"].pop("nat64_authenticated_udp"),
            lambda x: x["cases"].update({"unknown": {"status": "not_run", "evidence_sha256": None}}),
            lambda x: x.update({"private_key": "do-not-echo"}),
            lambda x: x["cases"]["wifi_system_dns"].update({"hostname": "do-not-echo"}),
            lambda x: x.update({"device_model": "serial-do-not-echo"}),
            lambda x: x.update({"schema": True}),
            lambda x: x.update({"recorded_at_utc": "2026-02-30T00:00:00Z"}),
        ):
            candidate = copy.deepcopy(self.report)
            mutate(candidate)
            with self.assertRaises(module.InvalidReport) as error:
                module.validate(candidate)
            self.assertNotIn("do-not-echo", str(error.exception))

    def test_observed_requires_attestation_and_digest(self):
        case = "wifi_system_dns"
        self.report["cases"][case] = {"status": "pass", "evidence_sha256": self.digest}
        with self.assertRaises(module.InvalidReport):
            module.validate(self.report)
        self.report["signed_device"] = True
        self.assertEqual(module.validate(self.report)["pass"], 1)
        for digest in (None, "0" * 64, "raw-private-data"):
            self.report["cases"][case]["evidence_sha256"] = digest
            with self.assertRaises(module.InvalidReport):
                module.validate(self.report)
        self.report["cases"][case] = {"status": "not_run", "evidence_sha256": self.digest}
        with self.assertRaises(module.InvalidReport):
            module.validate(self.report)

    def test_complete_exit_code_never_confuses_format_with_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"

            def run(complete=False):
                path.write_text(json.dumps(self.report), encoding="utf-8")
                args = [sys.executable, str(SCRIPT), "check", str(path)]
                if complete:
                    args.append("--require-complete")
                return subprocess.run(args, capture_output=True, text=True, check=False)

            self.assertEqual(run().returncode, 0)
            self.assertEqual(run(True).returncode, 1)
            self.report["signed_device"] = True
            for case in module.CASES:
                self.report["cases"][case] = {"status": "pass", "evidence_sha256": self.digest}
            self.assertEqual(run(True).returncode, 0)
            self.assertIn("Human review", run(True).stdout)
            self.report["cases"]["wifi_system_dns"]["status"] = "fail"
            self.assertEqual(run(True).returncode, 1)

    def test_duplicate_keys_and_oversize_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for data in (b'{"schema":1,"schema":1}', b" " * (module.MAX_BYTES + 1),
                         b'{"cases":{"wifi_system_dns":1,"wifi_system_dns":2}}',
                         b'{"invalid":"do-not-echo"', b"\xff"):
                path.write_bytes(data)
                with self.assertRaises(module.InvalidReport) as error:
                    module.load_report(path)
                self.assertNotIn("do-not-echo", str(error.exception))


if __name__ == "__main__":
    unittest.main()
