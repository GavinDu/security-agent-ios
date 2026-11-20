"""Offline unit tests for an exact, fail-closed tools-version header patch."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("wireguard_overlay", ROOT / "scripts/patch-wireguard-manifest.py")
overlay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay)

class ManifestTests(unittest.TestCase):
    def test_exact_patch(self):
        old = b"// swift-tools-version:5.3\nimport PackageDescription\n"
        self.assertEqual(overlay.fixed_manifest(old), b"// swift-tools-version:5.5\nimport PackageDescription\n")
    def test_preserves_unchanged_bytes(self):
        suffix = b"\x00\xff\nlet platforms = [.macOS(.v12), .iOS(.v15)]\n"
        self.assertEqual(overlay.fixed_manifest(overlay.OLD+suffix), overlay.NEW+suffix)
    def test_bad_headers_are_rejected(self):
        for data in (b"// swift-tools-version:5.5\n", b"// swift-tools-version:5.3.0\n",
                     b"// swift-tools-version:5.3\r\n", b"import PackageDescription\n"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                overlay.fixed_manifest(data)

if __name__ == "__main__":
    unittest.main()
