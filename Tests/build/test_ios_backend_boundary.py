"""Ensure BoringTun Rust is extension-only; static tests are not device proof."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
project = (ROOT / "Project.swift").read_text()

class BackendBoundaryTests(unittest.TestCase):
    def test_rust_linker_is_extension_only(self):
        app = project.split('name: "AgentApp",', 1)[1].split('name: "PacketTunnel",', 1)[0]
        ext = project.split('name: "PacketTunnel",', 1)[1].split('name: "AgentMac",', 1)[0]
        mac = project.split('name: "AgentMac",', 1)[1].split('name: "AgentAppTests",', 1)[0]
        self.assertIn('dependencies: [.target(name: "PacketTunnel")]', app)
        self.assertIn('build-boringtun.sh', ext)
        self.assertIn('product: .appExtension', ext)
        for text in (app, mac):
            self.assertNotIn('build-boringtun.sh', text)
            self.assertNotIn('WireGuardKit', text)
        self.assertNotIn('libwg-go', project)

    def test_main_app_imports_no_rust_or_wireguard_kit(self):
        for root in ("ios/AgentApp", "macos/AgentMac", "Shared"):
            for path in (ROOT / root).rglob("*.swift"):
                with self.subTest(path=str(path.relative_to(ROOT))):
                    source = path.read_text()
                    self.assertNotRegex(source, r"(?m)^\s*import\s+(WireGuardKit|BoringTun)\b")
                    self.assertNotIn("new_tunnel(", source)

    def test_network_endpoint_is_disambiguated(self):
        # NetworkExtension also declares NWEndpoint in the native iOS SDK.
        source = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
        self.assertIn("Network.NWEndpoint.Host", source)
        self.assertIn("Network.NWEndpoint.Port", source)
        self.assertNotIn("host: NWEndpoint.Host", source)
        self.assertNotIn("port: NWEndpoint.Port", source)
        self.assertNotIn("let port = NWEndpoint.Port", source)

    def test_single_source_of_truth_ffi_header(self):
        bridge = (ROOT / "ios/PacketTunnel/BoringTunBridge.h").read_text()
        self.assertIn('#include "wireguard_ffi.h"', bridge)
        self.assertNotIn("struct wireguard_result", bridge)

if __name__ == "__main__":
    unittest.main()
