"""Require truthful, redacted DNS failure propagation before Rust initialization."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
RESOLVER = (ROOT / "Shared/AsyncUnderlayDNSResolver.swift").read_text()
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
LINUX = (ROOT / "Tests/build/async_underlay_dns_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/AsyncUnderlayDNSResolverTests.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class DNSFailureReasonBoundaryTests(unittest.TestCase):
    def test_dns_errors_are_redacted_and_not_misattributed_to_rust(self):
        error = RESOLVER.split("enum UnderlayDNSResolutionError:", 1)[1].split(
            "final class UnderlayDNSCancellation", 1
        )[0]
        self.assertIn("Error, Equatable, LocalizedError", error)
        self.assertIn("var errorDescription: String?", error)
        for token in ("case .busy:", "case .timedOut:", "case .noAddresses:",
                      "case .lookupFailed:"):
            self.assertIn(token, error)
        self.assertNotIn("BoringTun", error)
        self.assertNotIn("host)", error)
        self.assertNotIn("host}", error)
        self.assertNotIn("\\(", error)
        for fragment in ("previous VPN DNS lookup", "DNS lookup timed out",
                         "no usable IP addresses", "check DNS and reconnect"):
            self.assertIn(fragment, error)

    def test_actual_transport_preserves_dns_failure_before_ffi_and_routes(self):
        start = TRANSPORT.split("func start(profile: ServerProfile", 1)[1].split(
            "private func networkSettings(", 1
        )[0]
        self.assertIn("case .failure(let error):", start)
        self.assertIn("self.fail(error)", start)
        self.assertNotIn("case .failure:\n                        self.fail(BoringTunError.initializationFailed)", start)
        self.assertIn("self.lifecycle.matches(epoch)", start)
        self.assertIn("dnsCancellation = self.dnsResolver.resolve(", start)
        self.assertLess(start.index("case .failure(let error):"),
                        start.index("ResolvedUnderlayCandidatePolicy.selectPinnedAddress("))
        self.assertLess(start.index("case .failure(let error):"),
                        start.index("codec = try BoringTunCodec("))
        self.assertLess(start.index("case .failure(let error):"),
                        start.index("provider.setTunnelNetworkSettings(settings)"))
        self.assertIn("self.dnsCancellation = nil", start)

    def test_real_production_swift_and_native_gates_remain_required(self):
        self.assertIn("async_underlay_dns_smoke.swift", WORKFLOW)
        self.assertIn("Shared/AsyncUnderlayDNSResolver.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("Tuist + macOS companion build", WORKFLOW)
        self.assertIn("expectedDescriptions:", LINUX)
        self.assertIn("uniqueDescriptions.count == 4", LINUX)
        self.assertIn("testDNSFailuresHaveRedactedDistinctDescriptions", NATIVE)
        self.assertIn("XCTAssertEqual(reason.localizedDescription, message)", NATIVE)


if __name__ == "__main__":
    unittest.main()
