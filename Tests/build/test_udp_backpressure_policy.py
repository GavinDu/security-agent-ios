"""Preserve bounded pending UDP sends without failing an active PacketTunnel."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
POLICY = (ROOT / "Shared/UDPBackpressurePolicy.swift").read_text()
SMOKE = (ROOT / "Tests/build/udp_backpressure_smoke.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class UDPBackpressureBoundaryTests(unittest.TestCase):
    def test_saturated_send_does_not_throw_or_enqueue(self):
        send = TRANSPORT.split("case .sendToNetwork(let datagram):", 1)[1].split(
            "case .writeIPv4", 1
        )[0]
        self.assertIn("UDPBackpressurePolicy.decision(", send)
        self.assertIn("case .drop:", send)
        self.assertIn("return", send.split("case .drop:", 1)[1].split("case .invalid:", 1)[0])
        self.assertLess(send.index("case .drop:"), send.index("pendingSends += 1"))
        self.assertIn("case .invalid:", send)
        self.assertIn("throw BoringTunError.engineError", send)
        self.assertIn("self.pendingSends -= 1", send)
        self.assertIn("if let error { self.fail(error) }", send)
        self.assertIn("self.lifecycle.matches(epoch)", send)

    def test_compiles_production_swift_policy_in_required_ci(self):
        self.assertIn("Shared/UDPBackpressurePolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/udp_backpressure_smoke.swift", WORKFLOW)
        self.assertIn("pendingSends == maxPendingSends ? .drop : .enqueue", POLICY)
        self.assertIn("pendingSends: limit, maxPendingSends: limit", SMOKE)
        self.assertIn("pendingSends: 0, maxPendingSends: 0", SMOKE)


if __name__ == "__main__":
    unittest.main()
