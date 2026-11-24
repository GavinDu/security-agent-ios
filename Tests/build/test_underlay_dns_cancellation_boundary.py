"""Guard actual PacketTunnel DNS token ownership and callback cancellation."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
RESOLVER = (ROOT / "Shared/AsyncUnderlayDNSResolver.swift").read_text()
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
SMOKE = (ROOT / "Tests/build/async_underlay_dns_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/AsyncUnderlayDNSCancellationTests.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class UnderlayDNSCancellationBoundaryTests(unittest.TestCase):
    def test_resolver_all_exit_paths_return_thread_safe_token(self):
        self.assertIn("final class UnderlayDNSCancellation", RESOLVER)
        self.assertIn("private let lock = NSLock()", RESOLVER)
        self.assertIn("var isCancelled: Bool", RESOLVER)
        self.assertIn("let cancellation = UnderlayDNSCancellation()", RESOLVER)
        resolve = RESOLVER.split("    func resolve(", 1)[1].split(
            "private final class UnderlayDNSOnce", 1
        )[0]
        self.assertGreaterEqual(resolve.count("return cancellation"), 4)
        self.assertIn("if !cancellation.isCancelled { completion(.failure(.busy)) }", resolve)
        self.assertIn("if !cancellation.isCancelled { completion(.failure(.lookupFailed)) }", resolve)
        self.assertIn("if !cancellation.isCancelled { completion(.failure(.timedOut)) }", resolve)
        self.assertIn("let once = UnderlayDNSOnce(", resolve)
        self.assertIn("callbackQueue.asyncAfter", resolve)
        self.assertIn("lookupInFlight = false", resolve)
        self.assertIn("once.finish(result)", resolve)
        token = RESOLVER.split("final class UnderlayDNSCancellation", 1)[1].split(
            "final class AsyncUnderlayDNSResolver", 1
        )[0]
        self.assertNotIn("lookupInFlight", token)
        self.assertIn("callbackQueue.async { [completion, cancellation] in", RESOLVER)
        self.assertIn("if !cancellation.isCancelled { completion(result) }", RESOLVER)

    def test_packet_tunnel_cancels_before_rust_and_udp_teardown(self):
        self.assertIn("private var dnsCancellation: UnderlayDNSCancellation?", TRANSPORT)
        start = TRANSPORT.split("func start(profile: ServerProfile", 1)[1].split(
            "private func startResolved(", 1
        )[0]
        self.assertIn("self.dnsCancellation = self.dnsResolver.resolve(", start)
        self.assertIn("self.dnsCancellation = nil", start)
        self.assertIn("self.lifecycle.matches(epoch)", start)
        teardown = TRANSPORT.split("private func teardown() {", 1)[1].split(
            "func stop(completion:", 1
        )[0]
        self.assertIn("dnsCancellation?.cancel()", teardown)
        self.assertIn("dnsCancellation = nil", teardown)
        self.assertLess(teardown.index("dnsCancellation?.cancel()"), teardown.index("codec = nil"))
        self.assertLess(teardown.index("dnsCancellation?.cancel()"), teardown.index("udp?.cancel()"))
        self.assertIn("ResolvedUnderlayCandidatePolicy.selectPinnedAddress(", TRANSPORT)
        self.assertIn("networkSettings(profile: profile, remoteHost: pinnedHost)", TRANSPORT)

    def test_production_swift_and_native_tests_are_wired(self):
        self.assertIn("Shared/AsyncUnderlayDNSResolver.swift", WORKFLOW)
        self.assertIn("Tests/build/async_underlay_dns_smoke.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build -p 'test_*.py' -v", WORKFLOW)
        self.assertIn("cancelWorkerRelease.signal()", SMOKE)
        self.assertIn("canceledDelivered.wait(", SMOKE)
        self.assertIn("invalid.cancel()", SMOKE)
        self.assertIn("testCancelledMalformedHostCannotDeliverAlreadyQueuedCallback", NATIVE)
        self.assertIn("testCanceledBlockedLookupStillRefusesConcurrentWorker", NATIVE)


if __name__ == "__main__":
    unittest.main()
