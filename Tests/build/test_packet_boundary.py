"""Guard both sides of the NEPacketTunnelFlow / BoringTun Rust C ABI."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class PacketBoundaryTests(unittest.TestCase):
    def test_validates_ingress_and_authenticated_output(self):
        transport = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
        delivery = (ROOT / "Shared/WireGuardInnerPacketDelivery.swift").read_text()
        # The ingress path still checks before calling Rust; decrypted egress
        # now validates in the production shared delivery helper before utun.
        self.assertIn("IPPacketEnvelope.isValid(packet, family: family)", transport)
        self.assertIn("IPPacketEnvelope.isValid(packet, family: family)", delivery)
        self.assertIn("try deliverInnerPacket(packet, family: .ipv4, protocolFamily: AF_INET)", transport)
        self.assertIn("try deliverInnerPacket(packet, family: .ipv6, protocolFamily: AF_INET6)", transport)
        self.assertIn("codec.encapsulate(packet)", transport)
        self.assertIn("provider.packetFlow.writePackets", transport)
        self.assertIn("guard write(packet) else {", delivery)
        self.assertIn("throw DeliveryError.writeRejected", delivery)

    def test_pure_bounded_validator_is_shared_with_native_xctest(self):
        source = (ROOT / "Shared/IPPacketEnvelope.swift").read_text()
        self.assertIn("maxInnerBytes = 65_536", source)
        self.assertIn("packet.withUnsafeBytes", source)
        self.assertIn("headerBytes <= bytes.count", source)
        self.assertIn("totalBytes == bytes.count", source)
        self.assertIn("payloadBytes + 40 == bytes.count", source)
        self.assertNotIn("import NetworkExtension", source)

if __name__ == "__main__":
    unittest.main()
