"""A mismatched local Apple utun read callback must not vanish inside zip."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
CODEC = (ROOT / "ios/PacketTunnel/BoringTunCodec.swift").read_text()
POLICY = (ROOT / "Shared/WireGuardPacketReadBatchPolicy.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
NATIVE = (ROOT / "Tests/iOS/WireGuardPacketReadBatchPolicyTests.swift").read_text()


class WireGuardPacketReadBatchBoundaryTests(unittest.TestCase):
    def test_actual_read_path_checks_local_callback_before_zip_and_rust(self):
        read = TRANSPORT.split("private func readPackets() {", 1)[1].split(
            "private func finishStart(", 1
        )[0]
        assert_block = "WireGuardPacketReadBatchPolicy.accepts("
        self.assertIn("provider.packetFlow.readPackets", read)
        self.assertIn(assert_block, read)
        self.assertIn("packetCount: packets.count", read)
        self.assertIn("protocolCount: protocols.count", read)
        self.assertIn("self.fail(BoringTunError.packetFlowReadFailed)", read)
        self.assertLess(read.index(assert_block), read.index("zip(packets, protocols)"))
        self.assertLess(read.index(assert_block), read.index("codec.encapsulate(packet)"))
        self.assertIn("guard let codec = self.codec else {", read)
        self.assertIn("self.fail(BoringTunError.stopped)", read)
        self.assertIn("IPPacketEnvelope.isValid(packet, family: family)", read)
        self.assertIn("if packets.isEmpty {", read)

    def test_local_error_is_explicit_not_a_remote_crypto_rejection(self):
        self.assertIn("case packetFlowReadFailed", CODEC)
        self.assertIn("case .packetFlowReadFailed:", CODEC)
        self.assertIn("packetCount >= 0", POLICY)
        self.assertIn("protocolCount >= 0", POLICY)
        self.assertIn("packetCount == protocolCount", POLICY)
        self.assertNotIn("import NetworkExtension", POLICY)

    def test_production_swift_executes_and_native_tests_are_required(self):
        self.assertIn("Shared/WireGuardPacketReadBatchPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/wireguard_packet_read_batch_smoke.swift", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn("testMismatchesAndImpossibleNegativeCountsFailClosed", NATIVE)


if __name__ == "__main__":
    unittest.main()
