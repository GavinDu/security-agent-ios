"""Make the SwiftUI iPhone/Mac apps independent of the Go tunnel backend.

The iOS packet-tunnel target alone owns WireGuardKit and its native Go archive.
Source/config checks do not substitute for xcodebuild target-link evidence.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
project = (ROOT / "Project.swift").read_text()


class BackendBoundaryTests(unittest.TestCase):
    def test_extension_owns_go_bridge(self):
        app = project.split('name: "AgentApp",', 1)[1].split('name: "PacketTunnel",', 1)[0]
        tunnel = project.split('name: "PacketTunnel",', 1)[1].split('name: "AgentMac",', 1)[0]
        mac = project.split('name: "AgentMac",', 1)[1].split('name: "AgentAppTests",', 1)[0]
        self.assertIn('dependencies: [.target(name: "PacketTunnel")]', app)
        self.assertNotIn('external(name: "WireGuardKit")', app)
        self.assertNotIn('build-wireguard-go.sh', app)
        self.assertIn('product: .appExtension', tunnel)
        self.assertIn('external(name: "WireGuardKit")', tunnel)
        self.assertIn('scripts/build-wireguard-go.sh', tunnel)
        self.assertNotIn('external(name: "WireGuardKit")', mac)
        self.assertNotIn('build-wireguard-go.sh', mac)

    def test_swiftui_and_shared_code_do_not_import_wireguard(self):
        for root in ("ios/AgentApp", "macos/AgentMac", "Shared"):
            for path in (ROOT / root).rglob("*.swift"):
                with self.subTest(path=str(path.relative_to(ROOT))):
                    code = path.read_text()
                    self.assertNotRegex(code, r"(?m)^\s*import\s+WireGuardKit(?:Go|C)?\b")
                    self.assertNotIn("wgTurnOn(", code)

if __name__ == "__main__":
    unittest.main()
