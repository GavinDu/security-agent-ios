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

    def test_rejects_dirty_tracked_staged_and_untracked_sources(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            checkout = Path(folder)
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            source = checkout / "Sources" / "WireGuardKitGo"
            source.mkdir(parents=True)
            manifest = checkout / "Package.swift"
            manifest.write_bytes(overlay.OLD + b"import PackageDescription\n")
            makefile = source / "Makefile"
            makefile.write_text("build:\n\t@echo safe\n")
            subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(checkout), "-c", "user.name=CI Fixture",
                 "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"],
                check=True
            )
            overlay.apply(checkout)
            overlay.apply(checkout, check_only=True)
            # Dirty tracked Makefile must fail even though HEAD is unchanged.
            makefile.write_text("build:\n\t@echo injected\n")
            with self.assertRaises(ValueError):
                overlay.apply(checkout, check_only=True)
            subprocess.run(["git", "-C", str(checkout), "checkout", "--", "Sources/WireGuardKitGo/Makefile"], check=True)
            # Staged content is never a permitted manifest overlay.
            subprocess.run(["git", "-C", str(checkout), "add", "Package.swift"], check=True)
            with self.assertRaises(ValueError):
                overlay.apply(checkout, check_only=True)
            subprocess.run(["git", "-C", str(checkout), "reset", "-q", "HEAD", "--", "Package.swift"], check=True)
            injected = source / "injected.go"
            injected.write_text("package main\n")
            with self.assertRaises(ValueError):
                overlay.apply(checkout, check_only=True)
            injected.unlink()
            overlay.apply(checkout, check_only=True)
            manifest.write_bytes(overlay.OLD + b"import PackageDescription\n")
            with self.assertRaises(ValueError):
                overlay.apply(checkout, check_only=True)

    def test_idempotent_checkout_patch_and_tamper_rejection(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            checkout = Path(folder)
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            manifest = checkout / "Package.swift"
            manifest.write_bytes(overlay.OLD + b"import PackageDescription\n")
            subprocess.run(["git", "-C", str(checkout), "add", "Package.swift"], check=True)
            subprocess.run(
                ["git", "-C", str(checkout), "-c", "user.name=CI Fixture",
                 "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"],
                check=True
            )
            overlay.apply(checkout)
            expected = manifest.read_bytes()
            overlay.apply(checkout)
            self.assertEqual(manifest.read_bytes(), expected)
            manifest.write_bytes(expected + b"// unauthorized mutation\n")
            with self.assertRaises(ValueError):
                overlay.apply(checkout)

if __name__ == "__main__":
    unittest.main()
