"""Ensure a rejected NEPacketTunnelFlow write fails the local VPN session."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
CODEC = (ROOT / "ios/PacketTunnel/BoringTunCodec.swift").read_text()
POLICY = (ROOT / "Shared/WireGuardInnerPacketDelivery.swift").read_text()
ENVELOPE = (ROOT / "Shared/IPPacketEnvelope.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
NATIVE = (ROOT / "Tests/iOS/WireGuardInnerPacketDeliveryTests.swift").read_text()


class InnerPacketFlowDeliveryBoundaryTests(unittest.TestCase):
    def test_both_ipv4_and_ipv6_actions_use_checked_delivery(self):
        process = TRANSPORT.split("private func process(_ action: BoringTunAction) throws {", 1)[1].split(
            "private func deliverInnerPacket(", 1
        )[0]
        self.assertIn("case .writeIPv4(let packet):", process)
        self.assertIn("try deliverInnerPacket(packet, family: .ipv4, protocolFamily: AF_INET)", process)
        self.assertIn("case .writeIPv6(let packet):", process)
        self.assertIn("try deliverInnerPacket(packet, family: .ipv6, protocolFamily: AF_INET6)", process)
        self.assertNotIn("provider?.packetFlow.writePackets(", process)

    def test_local_failure_is_never_silently_dropped_or_remote_auth_reclassified(self):
        delivery = TRANSPORT.split("private func deliverInnerPacket(", 1)[1].split(
            "private func readPackets()", 1
        )[0]
        self.assertIn("guard let provider else { throw BoringTunError.stopped }", delivery)
        self.assertIn("try WireGuardInnerPacketDelivery.deliver(packet, family: family)", delivery)
        self.assertIn("provider.packetFlow.writePackets(", delivery)
        self.assertIn("[validated], withProtocols: [NSNumber(value: protocolFamily)]", delivery)
        self.assertIn("throw BoringTunError.packetFlowWriteFailed", delivery)
        self.assertIn("case packetFlowWriteFailed", CODEC)
        self.assertIn("case .packetFlowWriteFailed:", CODEC)
        receive = TRANSPORT.split("private func receiveDatagram()", 1)[1].split(
            "private func process(_ action:", 1
        )[0]
        self.assertIn("do { try self.process(action) } catch { self.fail(error); return }", receive)
        self.assertIn("private func fail(_ error: Error)", TRANSPORT)
        self.assertNotIn("try? self.process(action)", receive)

    def test_production_helper_validates_before_utun_bool_and_throws_on_false(self):
        self.assertIn("IPPacketEnvelope.isValid(packet, family: family)", POLICY)
        self.assertIn("guard write(packet) else {", POLICY)
        self.assertIn("throw DeliveryError.writeRejected", POLICY)
        self.assertIn("static let maxInnerBytes = 65_536", ENVELOPE)
        self.assertIn("testSystemTunRefusesValidDecryptedFrameAndMustStopSession", NATIVE)
        self.assertIn("testMalformedPacketsNeverTouchTheSystemTun", NATIVE)
        self.assertIn("Shared/WireGuardInnerPacketDelivery.swift", WORKFLOW)
        self.assertIn("Tests/build/wireguard_inner_packet_delivery_smoke.swift", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("Tuist + macOS companion build", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
