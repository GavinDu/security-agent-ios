"""No blanket Rust FFI decapsulation error suppression in PacketTunnel."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
POLICY = (ROOT / "Shared/WireGuardDatagramFailurePolicy.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class WireGuardDatagramFailureBoundaryTests(unittest.TestCase):
    def test_rust_decapsulation_errors_are_classified_not_blanket_suppressed(self):
        receive = TRANSPORT.split("private func receiveDatagram()", 1)[1].split(
            "private func process(", 1
        )[0]
        self.assertNotIn("try? codec.decapsulate(packet)", receive)
        self.assertIn("action = try codec.decapsulate(packet)", receive)
        self.assertIn("case BoringTunError.invalidPacket:", receive)
        self.assertIn("reason = .malformedIncomingPacket", receive)
        self.assertIn("case BoringTunError.engineError:", receive)
        self.assertIn("reason = .authenticationRejected", receive)
        self.assertIn("case BoringTunError.invalidResponse:", receive)
        self.assertIn("reason = .malformedFFIResponse", receive)
        self.assertIn("reason = .unexpectedLocalFailure", receive)
        self.assertIn("WireGuardDatagramFailurePolicy.disposition(for: reason)", receive)
        self.assertIn("self.fail(error)", receive)
        self.assertIn("do { try self.process(action) } catch { self.fail(error); return }", receive)
        self.assertLess(receive.index("action = try codec.decapsulate(packet)"),
                        receive.index("if let action {"))

    def test_local_integrity_failure_stops_production_policy(self):
        self.assertIn("case .malformedIncomingPacket, .authenticationRejected:", POLICY)
        self.assertIn("return .discard", POLICY)
        self.assertIn("case .malformedFFIResponse, .unexpectedLocalFailure:", POLICY)
        self.assertIn("return .stopTunnel", POLICY)

    def test_actual_swift_linux_and_native_regression_required(self):
        self.assertIn("Shared/WireGuardDatagramFailurePolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/wireguard_datagram_failure_smoke.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertTrue((ROOT / "Tests/iOS/WireGuardDatagramFailurePolicyTests.swift").exists())


if __name__ == "__main__":
    unittest.main()
