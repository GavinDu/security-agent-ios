"""Ensure human-facing WireGuard underlay validation matches actual strict input gates."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONFIG = (ROOT / "Shared/AgentConfig.swift").read_text()
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
DNS_POLICY = (ROOT / "Shared/ResolvedUnderlayCandidatePolicy.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/UnsafeUnderlayEndpointMessageTests.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class UnderlayErrorDescriptionTests(unittest.TestCase):
    def test_production_error_truthfully_explains_unicast_and_dns(self):
        message = CONFIG.split("case .unsafeUnderlayEndpoint: return ", 1)[1].split(
            "\n", 1
        )[0]
        for required in [
            "usable unicast", "outside the VPN split routes",
            "resolved A/AAAA addresses are all safe",
            "Loopback", "link-local", "multicast", "broadcast",
        ]:
            self.assertIn(required, message)
        self.assertNotIn("Use the Mac's LAN/public address or hostname instead.", message)
        self.assertNotIn("full tunnel", message.lower())
        self.assertIn(
            "resolves and pins safe numeric A/AAAA before installing split routes",
            CONFIG,
        )

    def test_error_is_emitted_by_the_actual_start_boundary(self):
        self.assertIn(
            "throw AgentConfigurationError.unsafeUnderlayEndpoint", CONFIG
        )
        self.assertIn(
            "throw AgentConfigurationError.unsafeUnderlayEndpoint", TRANSPORT
        )
        self.assertIn("ResolvedUnderlayCandidatePolicy.selectPinnedAddress(", TRANSPORT)
        self.assertIn("TunnelUnderlayPolicy.permitsLiteralEndpoint(", CONFIG)
        self.assertIn("!addresses.isEmpty, addresses.count <= 32", DNS_POLICY)

    def test_real_native_xctest_runs_in_unchanged_required_ci(self):
        self.assertIn("testUnsafeEndpointDescriptionExplainsActualUnicastAndDNSPreflight", NATIVE)
        self.assertIn("XCTAssertFalse(message.contains(\"full tunnel\"))", NATIVE)
        self.assertIn('sources: ["Tests/iOS/**/*.swift"]', (ROOT / "Project.swift").read_text())
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("Tuist + macOS companion build", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
