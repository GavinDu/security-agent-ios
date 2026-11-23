"""Guard actual iOS NEPacketTunnelFlow AF policy before Int32 narrowing or Rust."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
CODEC = (ROOT / "ios/PacketTunnel/BoringTunCodec.swift").read_text()
POLICY = (ROOT / "Shared/WireGuardReadProtocolPolicy.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
NATIVE = (ROOT / "Tests/iOS/WireGuardReadProtocolPolicyTests.swift").read_text()


class WireGuardReadProtocolBoundaryTests(unittest.TestCase):
    def test_exact_numeric_family_before_narrowing_and_codec(self):
        read = TRANSPORT.split("private func readPackets() {", 1)[1].split(
            "private func finishStart(", 1
        )[0]
        gate = "WireGuardReadProtocolPolicy.accepts("
        self.assertIn(gate, read)
        self.assertIn("ipv4: AF_INET, ipv6: AF_INET6", read)
        self.assertIn("self.fail(BoringTunError.packetFlowReadFailed)", read)
        self.assertIn("provider.packetFlow.readPackets", read)
        self.assertLess(read.index(gate), read.index("proto.int32Value"))
        self.assertLess(read.index(gate), read.index("codec.encapsulate(packet)"))
        self.assertNotIn("default: continue", read)
        self.assertIn("WireGuardPacketReadBatchPolicy.accepts(", read)
        self.assertLess(read.index("WireGuardPacketReadBatchPolicy.accepts("), read.index(gate))
        self.assertIn("IPPacketEnvelope.isValid(packet, family: family)", read)
        self.assertIn("if packets.isEmpty {", read)

    def test_pure_foundation_policy_compares_without_narrowing(self):
        self.assertIn("number.compare(NSNumber(value: ipv4))", POLICY)
        self.assertIn("number.compare(NSNumber(value: ipv6))", POLICY)
        self.assertNotIn("int32Value", POLICY.split("static func accepts(", 1)[1])
        self.assertNotIn("import NetworkExtension", POLICY)
        self.assertIn("case packetFlowReadFailed", CODEC)

    def test_production_swift_linux_and_native_ios_gate(self):
        self.assertIn("Shared/WireGuardReadProtocolPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/wireguard_read_protocol_smoke.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("testLargeNSNumberCannotMasqueradeAsAFInetOrAFInet6", NATIVE)


if __name__ == "__main__":
    unittest.main()
