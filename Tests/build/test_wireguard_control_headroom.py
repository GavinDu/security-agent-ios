"""Outgoing BoringTun handshake/rekey capacity must survive data storms."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
POLICY = (ROOT / "Shared/WireGuardControlHeadroomPolicy.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
XCTEST = (ROOT / "Tests/iOS/WireGuardControlHeadroomPolicyTests.swift").read_text()

class WireGuardControlHeadroomBoundaryTests(unittest.TestCase):
    def test_transport_preserves_both_backpressure_and_headroom(self):
        send = TRANSPORT.split("case .sendToNetwork(let datagram):", 1)[1].split("case .writeIPv4", 1)[0]
        self.assertIn("UDPBackpressurePolicy.decision(", send)
        self.assertIn("WireGuardControlHeadroomPolicy.decision(", send)
        self.assertLess(send.index("UDPBackpressurePolicy.decision("),
                        send.index("WireGuardControlHeadroomPolicy.decision("))
        self.assertLess(send.index("WireGuardControlHeadroomPolicy.decision("),
                        send.index("pendingSends += 1"))
        self.assertIn("reservedControlSlots: 8", send)
        self.assertEqual(send.count("case .drop:"), 2)
        self.assertEqual(send.count("case .invalid:"), 2)
        self.assertIn("if let error { self.fail(error) }", send)

    def test_unknown_or_truncated_wireguard_header_is_never_prioritized(self):
        self.assertIn("datagram[1] == 0, datagram[2] == 0, datagram[3] == 0", POLICY)
        self.assertIn("case 1: guard datagram.count == 148", POLICY)
        self.assertIn("case 2: guard datagram.count == 92", POLICY)
        self.assertIn("case 3: guard datagram.count == 64", POLICY)
        self.assertIn("case 4: guard datagram.count >= 32", POLICY)
        self.assertIn("maxPendingSends - reservedControlSlots", POLICY)

    def test_required_compiled_and_native_tests_exist(self):
        self.assertIn("WireGuardControlHeadroomPolicy.swift", WORKFLOW)
        self.assertIn("wireguard_control_headroom_smoke.swift", WORKFLOW)
        self.assertIn("testControlPacketsUseHeadroomButNotExceedTotalCapacity", XCTEST)

if __name__ == "__main__":
    unittest.main()
