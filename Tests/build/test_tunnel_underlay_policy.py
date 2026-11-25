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
                        start.index("self.dnsResolver.resolve("))
        self.assertLess(start.index("self.dnsResolver.resolve("),
                        start.index("ResolvedUnderlayCandidatePolicy.selectPinnedAddress("))
        self.assertLess(start.index("ResolvedUnderlayCandidatePolicy.selectPinnedAddress("),
                        start.index("codec = try BoringTunCodec("))
        self.assertLess(start.index("ResolvedUnderlayCandidatePolicy.selectPinnedAddress("),
                        start.index("networkSettings(profile: profile, remoteHost: pinnedHost)"))
        self.assertIn("throw AgentConfigurationError.unsafeUnderlayEndpoint", start)

    def test_exact_private_route_before_dns_and_at_native_settings(self):
        start = TUNNEL.split("func start(profile: ServerProfile", 1)[1].split(
            "private func startResolved(", 1
        )[0]
        settings = TUNNEL.split("private func networkSettings(", 1)[1].split(
            "private func connect(", 1
        )[0]
        self.assertLess(start.index("TunnelUnderlayPolicy.privateAgentSplitRoutes("),
                        start.index("self.dnsResolver.resolve("))
        self.assertIn("guard profile.routeMode == .split else", settings)
        self.assertLess(settings.index("TunnelUnderlayPolicy.privateAgentSplitRoutes("),
                        settings.index("NEPacketTunnelNetworkSettings(tunnelRemoteAddress:"))
        self.assertIn("throw AgentConfigurationError.invalidSplitRoute", settings)
        self.assertNotIn("NEIPv4Route.default()", settings)
        self.assertNotIn("NEIPv6Route", settings)
        self.assertNotIn("NEDNSSettings", settings)
        self.assertNotIn("settings.dnsSettings", settings)
        self.assertNotIn("settings.ipv6Settings", settings)
        self.assertIn("Unapproved private split route accepted", SMOKE)

    def test_ddns_is_resolved_only_during_fresh_start(self):
        start = TUNNEL.split("func start(profile: ServerProfile", 1)[1].split(
            "private func startResolved(", 1
        )[0]
        self.assertEqual(TUNNEL.count("dnsResolver.resolve("), 1)
        self.assertIn("self.lifecycle.advance()", start)
        self.assertIn("self.lifecycle.matches(epoch)", start)
        self.assertIn("fresh preflight", start)
        self.assertIn("A ready connection retains its current pin.", start)
        self.assertIn("Fresh DDNS", (ROOT / "Tests/build/resolved_underlay_candidate_smoke.swift").read_text())
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("Shared/AsyncUnderlayDNSResolver.swift Tests/build/resolved_underlay_candidate_smoke.swift", workflow)

    def test_production_policy_rejects_aliases_and_cidrs(self):
        self.assertIn("canonicalIPv4(host)", POLICY)
        self.assertIn('text.lowercased().hasPrefix("0x")', POLICY)
        self.assertIn("nonEmptyLabels.allSatisfy", POLICY)
        # Mapped IPv4-in-IPv6 must be compared against the same installed
        # IPv4 CIDR route, not treated as an ordinary DNS hostname.
        self.assertIn("inet_pton(AF_INET6", POLICY)
        self.assertIn("mappedIPv4 & $0.mask == $0.network & $0.mask", POLICY)
        self.assertIn("::ffff:10.8.0.1", SMOKE)
        self.assertIn("::ffff:a08:1", SMOKE)
        self.assertIn("0x0a080001", SMOKE)
        self.assertIn("0x0a.0x08.0x00.0x01", SMOKE)
        self.assertIn("prefix == 0", POLICY)
        self.assertIn("splitIPv4Routes(", POLICY)
        self.assertIn("endpoint & route.mask == route.network & route.mask", POLICY)
        self.assertIn("TunnelUnderlayPolicy.privateAgentSplitRoutes(", TUNNEL)
        self.assertIn("RouteMode.split.allowedIPs", TUNNEL)
        self.assertIn("NEIPv4Route(destinationAddress: $0.destinationAddress", TUNNEL)
        self.assertNotIn('NEIPv4Route(destinationAddress: "10.8.0.0"', TUNNEL)
        self.assertIn("10.8.0.255", SMOKE)
        self.assertIn("10.8.0.001", SMOKE)
        self.assertIn("0.0.0.0/0", SMOKE)


if __name__ == "__main__":
    unittest.main()
