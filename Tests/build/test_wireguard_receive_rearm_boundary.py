"""Ensure empty Network.framework UDP callbacks cannot spin PacketTunnel's queue."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
POLICY = (ROOT / "Shared/WireGuardReceiveRearmPolicy.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class WireGuardReceiveRearmBoundaryTests(unittest.TestCase):
    def test_no_data_path_is_delayed_and_epoch_guarded(self):
        receive = TRANSPORT.split("private func receiveDatagram()", 1)[1].split(
            "private func process(", 1
        )[0]
        self.assertIn("self.receivingDatagram = false", receive)
        self.assertIn("if let error {", receive)
        self.assertIn("self.fail(error)", receive)
        self.assertIn("if WireGuardReceiveRearmPolicy.needsBackoff(", receive)
        self.assertIn("receivedByteCount: packet?.count", receive)
        self.assertIn("self.queue.asyncAfter(", receive)
        self.assertIn("self.lifecycle.matches(epoch)", receive)
        self.assertIn("WireGuardReceiveRearmPolicy.emptyReceiveDelayMilliseconds", receive)
        self.assertIn("} else {\n                    self.receiveDatagram()", receive)
        self.assertLess(receive.index("if let error {"),
                        receive.index("if WireGuardReceiveRearmPolicy.needsBackoff("))
        self.assertLess(receive.index("self.receivingDatagram = false"),
                        receive.index("self.queue.asyncAfter("))

    def test_ffi_error_and_path_watchdog_guards_are_preserved(self):
        self.assertIn("WireGuardDatagramFailurePolicy.disposition(for: reason)", TRANSPORT)
        self.assertIn("case .ready:\n            cancelPathWaitDeadline()", TRANSPORT)
        self.assertIn("case .waiting:", TRANSPORT)
        self.assertIn("startPathWaitDeadlineIfNeeded()", TRANSPORT)
        self.assertIn("cancelPathWaitDeadline()\n        udp?.stateUpdateHandler", TRANSPORT)
        self.assertIn("receivedByteCount <= 0", POLICY)

    def test_real_swift_and_native_xctest_are_mandatory(self):
        self.assertIn("Shared/WireGuardReceiveRearmPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/wireguard_receive_rearm_smoke.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertTrue((ROOT / "Tests/iOS/WireGuardReceiveRearmPolicyTests.swift").exists())


if __name__ == "__main__":
    unittest.main()
