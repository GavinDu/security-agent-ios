"""Reject retired protocol-engine source, build scripts and stale docs.

This guard intentionally scans active build surfaces, not historical Git
commits or issue discussions. It is run by existing Linux unittest CI.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
LEGACY = re.compile(
    r"(?i)(wireguardkit|wireguard-go|libwg-go|bootstrap-wireguard"
    r"|build-wireguard-go|(?:^|[^a-z])go\.mod\b|(?:^|[^a-z])go\.sum\b)"
)


class NoLegacyProtocolBackendTests(unittest.TestCase):
    def test_retired_files_are_absent(self):
        retired = (
            "docs/ADR-0001-IOS-VPN-BACKEND.md",
            "docs/WIREGUARD_BUILD.md",
            "scripts/build-wireguard-go.sh",
            "scripts/bootstrap-wireguard.sh",
            "go.mod", "go.sum",
        )
        for relative in retired:
            with self.subTest(relative=relative):
                self.assertFalse((ROOT / relative).exists())

    def test_no_legacy_code_or_build_hooks(self):
        paths = [ROOT / p for p in (
            "Project.swift", "Tuist/Package.swift", ".mise.toml",
            ".github/workflows/validate.yml", "scripts/setup-project.sh",
            "scripts/build-boringtun.sh", "scripts/bootstrap-boringtun.sh",
            "rust-toolchain.toml",
        )]
        for folder in ("ios", "macos", "Shared"):
            paths.extend((ROOT / folder).rglob("*.swift"))
        for path in paths:
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertTrue(path.is_file())
                self.assertIsNone(LEGACY.search(path.read_text()))
        for folder in ("ios", "macos", "Shared", "scripts", "Tuist"):
            self.assertFalse(list((ROOT / folder).rglob("*.go")))

    def test_active_documentation_has_no_obsolete_paths(self):
        for path in (ROOT / "docs").glob("*.md"):
            with self.subTest(path=path.name):
                content = path.read_text()
                self.assertNotIn("ADR-0001-IOS-VPN-BACKEND.md", content)
                self.assertNotIn("WIREGUARD_BUILD.md", content)
        for name in ("ARCHITECTURE.md", "ROADMAP.md",
                     "BORINGTUN_BUILD.md", "DEPENDENCIES.md"):
            with self.subTest(name=name):
                self.assertIsNone(LEGACY.search((ROOT / "docs" / name).read_text()))

    def test_rust_protocol_engine_is_preserved(self):
        project = (ROOT / "Project.swift").read_text()
        self.assertIn("Build pinned Rust BoringTun", project)
        self.assertIn("-lboringtun", project)
        self.assertIn("BoringTunBridge.h", project)
        self.assertIn("PacketTunnel", project)
        self.assertTrue((ROOT / "ios/PacketTunnel/BoringTunCodec.swift").is_file())


if __name__ == "__main__":
    unittest.main()
