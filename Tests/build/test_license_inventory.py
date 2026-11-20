"""Deterministic negative cases for the Cargo SPDX/lockfile inventory.

These fixtures test manifest policy only, not an iOS binary or legal review.
"""
import copy
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/audit-boringtun-licenses.py"
spec = importlib.util.spec_from_file_location("boringtun_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

ROOT = "path+file:///tmp/boringtun/boringtun#0.7.1"
DEP = "registry+https://github.com/rust-lang/crates.io-index#ring@0.17.0"


def fixtures():
    meta = {
        "version": 1,
        "packages": [
            {"id": ROOT, "name": "boringtun", "version": "0.7.1",
             "source": None, "license": "BSD-3-Clause"},
            {"id": DEP, "name": "ring", "version": "0.17.0",
             "source": audit.REGISTRY, "license": "ISC AND MIT AND OpenSSL"},
        ],
        "resolve": {
            "root": ROOT,
            "nodes": [{"id": ROOT, "deps": [{"pkg": DEP}]},
                      {"id": DEP, "deps": []}],
        },
    }
    lock = {"package": [
        {"name": "boringtun", "version": "0.7.1"},
        {"name": "ring", "version": "0.17.0", "source": audit.REGISTRY,
         "checksum": "a" * 64},
    ]}
    return meta, lock


class CargoLicenseInventoryTests(unittest.TestCase):
    def test_pinned_registry_package_with_checksum(self):
        meta, lock = fixtures()
        result = audit.inventory(meta, lock)
        self.assertEqual(result["package_count"], 2)
        self.assertEqual(result["packages"][0]["relationship"], "root")
        self.assertEqual(result["packages"][1]["relationship"], "direct")
        self.assertEqual(result["packages"][1]["checksum"], "a" * 64)
        self.assertEqual(result["target"], "aarch64-apple-ios")

    def test_reproducible_order(self):
        meta, lock = fixtures()
        self.assertEqual(audit.inventory(meta, lock), audit.inventory(meta, lock))

    def test_copyleft_requires_manual_review(self):
        meta, lock = fixtures()
        meta["packages"][1]["license"] = "GPL-3.0-only"
        with self.assertRaises(audit.InventoryError):
            audit.inventory(meta, lock)

    def test_missing_license_rejected(self):
        meta, lock = fixtures()
        meta["packages"][1]["license"] = None
        with self.assertRaises(audit.InventoryError):
            audit.inventory(meta, lock)

    def test_unreviewed_source_rejected(self):
        meta, lock = fixtures()
        meta["packages"][1]["source"] = "git+https://example.com/unreviewed"
        with self.assertRaises(audit.InventoryError):
            audit.inventory(meta, lock)

    def test_missing_checksum_rejected(self):
        meta, lock = fixtures()
        del lock["package"][1]["checksum"]
        with self.assertRaises(audit.InventoryError):
            audit.inventory(meta, lock)

    def test_wrong_version_rejected(self):
        meta, lock = fixtures()
        meta["packages"][0]["version"] = "0.6.0"
        with self.assertRaises(audit.InventoryError):
            audit.inventory(meta, lock)

    def test_not_in_lock_rejected(self):
        meta, lock = fixtures()
        lock["package"].pop()
        with self.assertRaises(audit.InventoryError):
            audit.inventory(meta, lock)

    def test_partial_resolve_graph_rejected(self):
        meta, lock = fixtures()
        meta["resolve"]["nodes"][0]["id"] = "nonexistent"
        with self.assertRaises(audit.InventoryError):
            audit.inventory(meta, lock)

    def test_invalid_license_expression_rejected(self):
        for expression in ("MIT Apache-2.0", "(MIT OR Apache-2.0", "MIT OR OR BSD-3-Clause",
                           "MIT/Apache-2.0", "MIT OR", "MIT AND GPL-2.0-only"):
            with self.subTest(expression=expression):
                with self.assertRaises(audit.InventoryError):
                    audit.check_license(expression)

    def test_parenthesized_permissive_expression(self):
        self.assertEqual(audit.check_license("(MIT OR Apache-2.0) AND BSD-3-Clause"),
                         "(MIT OR Apache-2.0) AND BSD-3-Clause")


if __name__ == "__main__":
    unittest.main()
