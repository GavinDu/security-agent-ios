"""Check DNS underlay selection occurs before routes, cryptography and UDP."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
RESOLVER = (ROOT / "Shared/AsyncUnderlayDNSResolver.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
TEST = (ROOT / "Tests/build/async_underlay_dns_smoke.swift").read_text()

class UnderlayDNSPreRouteTests(unittest.TestCase):
    def test_hostname_is_not_reused_after_dns_selection(self):
        start = TRANSPORT.split("func start(profile:", 1)[1].split("private func networkSettings(", 1)[0]
        self.assertIn("dnsResolver.resolve(", start)
        self.assertIn("let lookupHost = host.first ==", start)
        self.assertIn("ResolvedUnderlayCandidatePolicy.selectPinnedAddress(", start)
        self.assertIn("Network.IPv4Address(pinnedHost)", start)
        self.assertIn("Network.IPv6Address(pinnedHost)", start)
        self.assertIn("destination = .ipv4(address)", start)
        self.assertIn("destination = .ipv6(address)", start)
        self.assertIn("self.connect(host: destination, port: port)", start)
        self.assertIn("networkSettings(profile: profile, remoteHost: pinnedHost)", start)
        self.assertNotIn("Network.NWEndpoint.Host(host)", start)
        self.assertLess(start.index("dnsResolver.resolve("),
                        start.index("private func startResolved("))
        self.assertLess(start.index("ResolvedUnderlayCandidatePolicy.selectPinnedAddress("),
                        start.index("setTunnelNetworkSettings(settings)"))
        self.assertLess(start.index("ResolvedUnderlayCandidatePolicy.selectPinnedAddress("),
                        start.index("BoringTunCodec("))

    def test_single_flight_timeout_and_epoch_check(self):
        self.assertIn("private var lookupInFlight = false", RESOLVER)
        self.assertIn("host.utf8.count <= 253", RESOLVER)
        self.assertIn("guard let socketAddress = record.pointee.ai_addr", RESOLVER)
        self.assertIn("static let shared = AsyncUnderlayDNSResolver()", RESOLVER)
        self.assertIn("AsyncUnderlayDNSResolver.shared", TRANSPORT)
        self.assertIn("callbackQueue.asyncAfter", RESOLVER)
        self.assertIn("once.finish(.failure(.timedOut))", RESOLVER)
        self.assertIn("private var finished = false", RESOLVER)
        self.assertIn("lifecycle.matches(epoch)", TRANSPORT)
        self.assertIn("test", TEST.lower())
        self.assertIn("async_underlay_dns_smoke.swift", WORKFLOW)

if __name__ == "__main__":
    unittest.main()
