"""Reject unusable literal UDP peer IPs at profile boundary, before DNS/FFI."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
LITERAL = (ROOT / "Shared/TunnelUnderlayPolicy.swift").read_text()
RESOLVED = (ROOT / "Shared/ResolvedUnderlayCandidatePolicy.swift").read_text()
APP_CONFIG = (ROOT / "Shared/AgentConfig.swift").read_text()
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()


class LiteralUnderlayUnicastBoundaryTests(unittest.TestCase):
    def test_single_unicast_classification_is_shared_with_dns_policy(self):
        self.assertIn("static func usableIPv4Unicast(", LITERAL)
        self.assertIn("static func usableIPv6Unicast(", LITERAL)
        self.assertIn("guard usableIPv4Unicast(octets) else", LITERAL)
        self.assertIn("guard usableIPv6Unicast(ipv6) else", LITERAL)
        self.assertIn("guard usableIPv4Unicast(Array(ipv6.suffix(4)))", LITERAL)
        self.assertIn("let ipv4Compatible = octets.prefix(12)", LITERAL)
        self.assertIn("octets[0] != 127", LITERAL)
        self.assertIn("octets[0] < 224", LITERAL)
        self.assertIn("octets[0] != 0xff", LITERAL)
        self.assertIn("TunnelUnderlayPolicy.usableIPv4Unicast(octets)", RESOLVED)
        self.assertIn("TunnelUnderlayPolicy.usableIPv6Unicast(octets)", RESOLVED)
        self.assertNotIn("private static func usableIPv4Unicast", RESOLVED)

    def test_early_guard_precedes_crypto_routes_and_resolver(self):
        profile = APP_CONFIG.split("func validated() throws -> ServerProfile", 1)[1]
        self.assertIn("TunnelUnderlayPolicy.permitsLiteralEndpoint(", profile)
        start = TRANSPORT.split("func start(profile: ServerProfile", 1)[1].split(
            "private func networkSettings(", 1
        )[0]
        self.assertLess(
            start.index("TunnelUnderlayPolicy.permitsLiteralEndpoint("),
            start.index("dnsResolver.resolve("),
        )
        self.assertLess(
            start.index("dnsResolver.resolve("),
            start.index("codec = try BoringTunCodec("),
        )

    def test_real_linux_swift_and_native_xctest_prove_both_policies(self):
        literals = (ROOT / "Tests/build/tunnel_underlay_policy_smoke.swift").read_text()
        candidates = (ROOT / "Tests/build/resolved_underlay_candidate_smoke.swift").read_text()
        native = (ROOT / "Tests/iOS/TunnelUnderlayPolicyTests.swift").read_text()
        native_dns = (ROOT / "Tests/iOS/ResolvedUnderlayCandidatePolicyTests.swift").read_text()
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        for hostile in [
            '"255.255.255.255"', '"::1"', '"fe80::1"',
            '"ff02::1"', '"::10.8.0.1"', '"::ffff:127.0.0.1"',
        ]:
            self.assertIn(hostile, literals)
            self.assertIn(hostile, native)
        self.assertIn('"fd00::42"', literals)
        self.assertIn('"fd00::42"', candidates)
        self.assertIn('"fd00::42"', native_dns)
        self.assertIn("testRejectsUnusableLiteralIPv4IPv6AtEarlyProfileBoundary", native)
        self.assertIn("Shared/TunnelUnderlayPolicy.swift", workflow)
        self.assertIn("Tests/build/tunnel_underlay_policy_smoke.swift", workflow)
        self.assertIn("Tests/build/resolved_underlay_candidate_smoke.swift", workflow)
        self.assertIn("Tuist + iOS device and simulator XCTest", workflow)
        self.assertIn("Tuist + macOS companion build", workflow)


if __name__ == "__main__":
    unittest.main()
