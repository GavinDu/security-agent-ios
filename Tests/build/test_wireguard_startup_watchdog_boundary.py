"""Bound the *whole* BoringTun PacketTunnel startup, including Apple's settings callback."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
CODEC = (ROOT / "ios/PacketTunnel/BoringTunCodec.swift").read_text()
POLICY = (ROOT / "Shared/WireGuardStartupWatchdogPolicy.swift").read_text()
CI = (ROOT / ".github/workflows/validate.yml").read_text()


class StartupWatchdogBoundaryTests(unittest.TestCase):
    def test_armed_before_dns_and_network_settings(self):
        start = TRANSPORT.split("func start(profile:", 1)[1].split("private func startResolved(", 1)[0]
        self.assertIn("self.startCompletion = completion", start)
        self.assertIn("self.armStartupDeadline(epoch: epoch)", start)
        self.assertLess(start.index("self.armStartupDeadline(epoch: epoch)"), start.index("let validated = try profile.validated()"))
        self.assertIn("self.dnsResolver.resolve(", start)
        self.assertIn("provider.setTunnelNetworkSettings(settings)", TRANSPORT)

    def test_deadline_uses_epoch_and_terminates_pending_start_once(self):
        timer = TRANSPORT.split("private func armStartupDeadline(", 1)[1].split("private func networkSettings(", 1)[0]
        for text in (
            "DispatchSource.makeTimerSource(queue: queue)",
            "WireGuardStartupWatchdogPolicy.timeoutSeconds",
            "WireGuardStartupWatchdogPolicy.shouldExpire(",
            "pendingCompletion: self.startCompletion != nil",
            "expectedGeneration: epoch",
            "currentGeneration: self.lifecycle.current",
            "self.fail(BoringTunError.startupTimedOut)",
            "startupDeadline = timer",
            "timer.resume()",
        ):
            self.assertIn(text, timer)
        self.assertIn("case .startupTimedOut:", CODEC)
        self.assertIn("expectedGeneration != 0", POLICY)

    def test_completion_and_teardown_cancel_pending_timer(self):
        completed = TRANSPORT.split("private func finishStart(", 1)[1].split("private func fail(", 1)[0]
        self.assertLess(completed.index("startupDeadline?.cancel()"), completed.index("completion?(error)"))
        teardown = TRANSPORT.split("private func teardown()", 1)[1].split("func stop(", 1)[0]
        self.assertLess(teardown.index("startupDeadline?.cancel()"), teardown.index("udp?.cancel()"))
        self.assertIn("if wasStarting {\n            finishStart(error)", TRANSPORT)

    def test_actual_swift_execution_and_native_tests_required(self):
        self.assertIn("Shared/WireGuardStartupWatchdogPolicy.swift", CI)
        self.assertIn("Tests/build/wireguard_startup_watchdog_smoke.swift", CI)
        self.assertTrue((ROOT / "Tests/iOS/WireGuardStartupWatchdogPolicyTests.swift").exists())


if __name__ == "__main__":
    unittest.main()
