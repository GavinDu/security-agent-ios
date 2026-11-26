"""Check the pinned Rust queue continuation at the actual Swift/C boundary."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CODEC = (ROOT / "ios/PacketTunnel/BoringTunCodec.swift").read_text()
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
POLICY = (ROOT / "Shared/BoringTunPendingDrainPolicy.swift").read_text()
WF = (ROOT / ".github/workflows/validate.yml").read_text()


class PendingDrainBoundaryTests(unittest.TestCase):
    def test_nonnull_local_continuation_and_remote_empty_rejection(self):
        remote = CODEC.split("func decapsulate(", 1)[1].split("func drainQueuedPackets(", 1)[0]
        self.assertIn("guard !datagram.isEmpty", remote)
        local = CODEC.split("func drainQueuedPackets(", 1)[1].split("var hasAuthenticatedHandshake", 1)[0]
        self.assertIn("withUnsafePointer(to: &sentinel)", local)
        self.assertIn("wireguard_read(handle, pointer, 0,", local)
        self.assertIn("case .done: return false", local)
        self.assertIn("case .writeIPv4, .writeIPv6:", local)
        self.assertIn("throw BoringTunError.invalidResponse", local)
        self.assertIn("maxCalls = 257", POLICY)
        self.assertIn("throw Failure.limitExceeded", POLICY)

    def test_drain_before_handshake_completion_and_rearm(self):
        receive = TRANSPORT.split("private func receiveDatagram()", 1)[1].split("private func process(", 1)[0]
        self.assertLess(receive.index("if case .sendToNetwork = action"), receive.index("codec.drainQueuedPackets"))
        self.assertLess(receive.index("codec.drainQueuedPackets"), receive.index("codec.hasAuthenticatedHandshake"))
        self.assertIn("try self.process(.sendToNetwork(datagram))", receive)
        self.assertIn("self.fail(error)", receive)
        self.assertIn("self.lifecycle.matches(epoch)", receive)

    def test_real_rust_and_swift_regression_wired(self):
        self.assertIn("Shared/BoringTunPendingDrainPolicy.swift", WF)
        self.assertIn("boringtun_pending_drain_smoke.swift", WF)
        self.assertIn("boringtun_ffi_smoke.py", WF)
        self.assertTrue((ROOT / "Tests/iOS/BoringTunPendingDrainPolicyTests.swift").exists())


if __name__ == "__main__":
    unittest.main()
