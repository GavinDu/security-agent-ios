"""Conservative CycloneDX Cargo *source* SBOM conversion regressions."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "boringtun_source_sbom", ROOT / "scripts/emit-boringtun-sbom.py"
)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

EVIDENCE = "Normal/build Cargo resolution and Cargo.lock only; no dev dependencies or binary link map"


def fixture():
    return {
        "schema_version": 1,
        "target": "aarch64-apple-ios",
        "features": ["ffi-bindings"],
        "evidence": EVIDENCE,
        "package_count": 3,
        "packages": [
            {"name": "boringtun", "version": "0.7.1",
             "source": "pinned-upstream-root", "checksum": None,
             "license": "BSD-3-Clause", "relationship": "root"},
            {"name": "ring", "version": "0.17.14",
             "source": "crates.io", "checksum": "a" * 64,
             "license": "Apache-2.0 OR ISC", "relationship": "direct"},
            {"name": "libc", "version": "0.2.177",
             "source": "crates.io", "checksum": "b" * 64,
             "license": "MIT OR Apache-2.0", "relationship": "transitive-or-build"},
        ],
    }


class BoringTunSourceSBOMTests(unittest.TestCase):
    def test_deterministic_public_cyclonedx_with_locked_checksums(self):
        one = fixture()
        two = fixture()
        two["packages"].reverse()
        a, b = MOD.build_bom(one), MOD.build_bom(two)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertEqual(a["bomFormat"], "CycloneDX")
        self.assertEqual(a["specVersion"], "1.5")
        self.assertEqual([c["name"] for c in a["components"]], ["libc", "ring"])
        self.assertEqual(a["components"][0]["hashes"][0]["content"], "b" * 64)
        self.assertIn(MOD.PIN, str(a["metadata"]))
        self.assertNotIn("/home/runner/", str(a))
        self.assertNotIn("privateKey", str(a))
        self.assertIn("NOT final binary", str(a))

    def test_rejects_empty_duplicate_wrong_root_and_package_count(self):
        for mutate in (
            lambda x: x.update(packages=[], package_count=0),
            lambda x: x["packages"].append(x["packages"][1].copy()),
            lambda x: x.update(package_count=99),
            lambda x: x["packages"][0].update(version="0.6.0"),
            lambda x: x["packages"][0].update(source="crates.io"),
            lambda x: x["packages"].pop(0),
        ):
            obj = fixture()
            mutate(obj)
            with self.subTest(mutate=str(mutate)), self.assertRaises(MOD.SBOMError):
                MOD.build_bom(obj)

    def test_rejects_unreviewed_license_source_and_checksum(self):
        for field, bad in (
            ("license", "GPL-3.0-only"),
            ("license", "MIT OR"),
            ("source", "git+https://example.invalid"),
            ("checksum", "bad-checksum"),
            ("checksum", None),
            ("relationship", "dev"),
            ("name", "../passwd"),
            ("version", "0.1/unsafe"),
        ):
            obj = fixture()
            obj["packages"][1][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(MOD.SBOMError):
                MOD.build_bom(obj)

    def test_rejects_wrong_target_features_evidence_schema(self):
        for key, bad in (
            ("target", "x86_64-unknown-linux-gnu"),
            ("features", ["default"]),
            ("evidence", "final linked binary"),
            ("schema_version", 99),
            ("package_count", True),
        ):
            obj = fixture()
            obj[key] = bad
            with self.subTest(key=key), self.assertRaises(MOD.SBOMError):
                MOD.build_bom(obj)

    def test_workflow_retains_reviewed_inventory_gate_and_uploads_both(self):
        wf = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("scripts/audit-boringtun-licenses.py", wf)
        self.assertIn("scripts/emit-boringtun-sbom.py", wf)
        self.assertIn("boringtun-ios-license-inventory.json", wf)
        self.assertIn("boringtun-ios-source-sbom.json", wf)
        self.assertLess(wf.index("scripts/audit-boringtun-licenses.py"),
                        wf.index("scripts/emit-boringtun-sbom.py"))


if __name__ == "__main__":
    unittest.main()
