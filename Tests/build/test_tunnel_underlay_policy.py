"""Guard outer WireGuard UDP endpoint against the inner IPv4 split route."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONFIG = (ROOT / "Shared/AgentConfig.swift").read_text()
TUNNEL = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
POLICY = (ROOT / "Shared/TunnelUnderlayPolicy.swift").read_text()
SMOKE = (ROOT / "Tests/build/tunnel_underlay_policy_smoke.swift").read_text()


class TunnelUnderlayBoundaryTests(unittest.TestCase):
    def test_profile_validated_rejects_captured_underlay(self):
        validated = CONFIG.split("func validated() throws -> ServerProfile", 1)[1].split(
            "/// Pin the V2 digest schema", 1
        )[0]
        self.assertIn("TunnelUnderlayPolicy.permitsLiteralEndpoint(", validated)
        self.assertIn("RouteMode.split.allowedIPs", validated)
        self.assertIn("throw AgentConfigurationError.unsafeUnderlayEndpoint", validated)

    def test_extension_rejects_before_rust_codec_or_routes(self):
        start = TUNNEL.split("func start(profile: ServerProfile", 1)[1].split(
            "private func networkSettings(", 1
        )[0]
        self.assertLess(start.index("TunnelUnderlayPolicy.permitsLiteralEndpoint("),
                        start.index("BoringTunCodec("))
        self.assertLess(start.index("TunnelUnderlayPolicy.permitsLiteralEndpoint("),
                        start.index("self.networkSettings("))
        self.assertIn("throw AgentConfigurationError.unsafeUnderlayEndpoint", start)

    def test_production_policy_rejects_aliases_and_cidrs(self):
        self.assertIn("canonicalIPv4(host)", POLICY)
        self.assertIn('text.lowercased().hasPrefix("0x")', POLICY)
        self.assertIn("numericHostLabels.allSatisfy", POLICY)
        self.assertIn("0x0a080001", SMOKE)
        self.assertIn("0x0a.0x08.0x00.0x01", SMOKE)
        self.assertIn("prefix == 0", POLICY)
        self.assertIn("splitIPv4Routes(", POLICY)
        self.assertIn("endpoint & route.mask == route.network & route.mask", POLICY)
        self.assertIn("TunnelUnderlayPolicy.splitIPv4Routes(", TUNNEL)
        self.assertIn("RouteMode.split.allowedIPs", TUNNEL)
        self.assertIn("NEIPv4Route(destinationAddress: $0.destinationAddress", TUNNEL)
        self.assertNotIn('NEIPv4Route(destinationAddress: "10.8.0.0"', TUNNEL)
        self.assertIn("10.8.0.255", SMOKE)
        self.assertIn("10.8.0.001", SMOKE)
        self.assertIn("0.0.0.0/0", SMOKE)


if __name__ == "__main__":
    unittest.main()
