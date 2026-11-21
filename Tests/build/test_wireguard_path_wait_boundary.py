"""Authenticated NWConnection.waiting must have a bounded, epoch-safe recovery."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
MODEL = (ROOT / "Shared/WireGuardPathWaitGeneration.swift").read_text()
CODEC = (ROOT / "ios/PacketTunnel/BoringTunCodec.swift").read_text()
WF = (ROOT / ".github/workflows/validate.yml").read_text()

class WireGuardPathWaitBoundaryTests(unittest.TestCase):
    def test_ready_cancels_and_waiting_schedules_single_watchdog(self):
        body = TRANSPORT.split("private func connectionChanged(", 1)[1].split("private func receiveDatagram", 1)[0]
        self.assertIn("case .ready:\n            cancelPathWaitDeadline()", body)
        self.assertIn("case .waiting:\n", body)
        self.assertIn("startPathWaitDeadlineIfNeeded()", body)
        self.assertIn("guard active, startCompletion == nil,", body)
        self.assertIn("let token = pathWait.beginWait()", body)
        self.assertIn("timer.schedule(deadline: .now() + .seconds(30))", body)
        self.assertIn("self.lifecycle.matches(epoch)", body)
        self.assertIn("self.pathWait.accepts(token)", body)
        self.assertIn("self.fail(BoringTunError.networkPathTimedOut)", body)
        self.assertIn("case .networkPathTimedOut:", CODEC)

    def test_teardown_cancels_timer_before_socket_release(self):
        teardown = TRANSPORT.split("private func teardown()", 1)[1]
        self.assertLess(teardown.index("cancelPathWaitDeadline()"), teardown.index("udp?.cancel()"))
        self.assertIn("pathWait.invalidate()", TRANSPORT)
        self.assertIn("pathWaitDeadline?.cancel()", TRANSPORT)
        self.assertIn("waiting && token != 0 && token == current", MODEL)

    def test_real_swift_linux_and_native_tests_in_ci(self):
        self.assertIn("Shared/WireGuardPathWaitGeneration.swift", WF)
        self.assertIn("Tests/build/wireguard_path_wait_smoke.swift", WF)
        self.assertTrue((ROOT / "Tests/iOS/WireGuardPathWaitGenerationTests.swift").exists())

if __name__ == "__main__":
    unittest.main()
