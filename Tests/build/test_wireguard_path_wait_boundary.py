"""Authenticated NWConnection.waiting must have a bounded, epoch-safe recovery."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
MODEL = (ROOT / "Shared/WireGuardPathWaitGeneration.swift").read_text()
CODEC = (ROOT / "ios/PacketTunnel/BoringTunCodec.swift").read_text()
WF = (ROOT / ".github/workflows/validate.yml").read_text()

class WireGuardPathWaitBoundaryTests(unittest.TestCase):
    def test_ready_requires_fresh_start_and_waiting_schedules_single_watchdog(self):
        body = TRANSPORT.split("private func connectionChanged(", 1)[1].split("private func receiveDatagram", 1)[0]
        self.assertIn("guard !pathWait.requiresFreshStartOnReady else", body)
        self.assertLess(body.index("fail(BoringTunError.networkPathRevalidationRequired)"),
                        body.index("cancelPathWaitDeadline()"))
        self.assertLess(body.index("fail(BoringTunError.networkPathRevalidationRequired)"),
                        body.index("receiveDatagram()"))
        self.assertIn("provider?.reasserting = true", body)
        self.assertIn("case .networkPathRevalidationRequired:", CODEC)
        self.assertIn("case .waiting:\n", body)
        self.assertIn("startPathWaitDeadlineIfNeeded()", body)
        self.assertIn("guard active, startCompletion == nil,", body)
        self.assertIn("let token = pathWait.beginWait()", body)
        self.assertIn("timer.schedule(deadline: .now() + .seconds(30))", body)
        self.assertIn("self.lifecycle.matches(epoch)", body)
        self.assertIn("self.pathWait.accepts(token)", body)
        self.assertIn("self.fail(BoringTunError.networkPathTimedOut)", body)
        self.assertIn("case .networkPathTimedOut:", CODEC)

    def test_old_session_io_is_suspended_during_wait(self):
        for signature in ("private func receiveDatagram()", "private func readPackets()",
                          "private func process("):
            body = TRANSPORT.split(signature, 1)[1].split("\n    }", 1)[0]
            self.assertIn("pathWait.permitsEngineIO", body)
        self.assertGreaterEqual(TRANSPORT.count("guard self.pathWait.permitsEngineIO"), 2)
        self.assertIn("self.pathWait.permitsEngineIO,\n                          let codec", TRANSPORT)
        self.assertIn("self.provider?.reasserting = false\n                        self.finishStart(nil)", TRANSPORT)
        self.assertIn("var permitsEngineIO: Bool { !waiting }", MODEL)
        self.assertIn("var requiresFreshStartOnReady: Bool { waiting }", MODEL)

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
