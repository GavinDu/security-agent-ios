"""Verify bounded, fail-closed native utun callback before Rust C FFI."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "Shared/WireGuardPacketReadBatchPolicy.swift").read_text()
TRANSPORT = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
LINUX = (ROOT / "Tests/build/wireguard_packet_read_batch_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/WireGuardPacketReadBatchPolicyTests.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class WireGuardPacketReadBudgetTests(unittest.TestCase):
    def test_production_count_and_byte_limits_are_bounded(self):
        for token in (
            "static let maxPacketsPerBatch = 256",
            "static let maxPacketBytes = 65_536",
            "static let maxBatchBytes = 8 * 1_024 * 1_024",
            "packetCount <= maxPacketsPerBatch",
            "packetCount == protocolCount",
            "lengths.count <= maxPacketsPerBatch",
            "size > 0",
            "size <= maxPacketBytes",
            "size <= maxBatchBytes - total",
        ):
            self.assertIn(token, POLICY)
        self.assertNotIn("total + size <= maxBatchBytes", POLICY)
        self.assertIn("precondition(!accepts(Int.max, Int.max)", LINUX)
        self.assertIn("Array(repeating: 65_536, count: 129)", LINUX)
        self.assertIn("testPayloadBudgetRejectsLocalOversizeAndOverflow", NATIVE)

    def test_actual_native_read_rejects_before_rust_and_zip(self):
        read = TRANSPORT.split("private func readPackets() {", 1)[1].split(
            "private func finishStart(", 1
        )[0]
        c = read.index("WireGuardPacketReadBatchPolicy.accepts(")
        b = read.index("WireGuardPacketReadBatchPolicy.acceptsPayloadLengths(")
        ff = read.index("codec.encapsulate(packet)")
        zip_index = read.index("zip(packets, protocols)")
        self.assertLess(c, b)
        self.assertLess(b, zip_index)
        self.assertLess(b, ff)
        self.assertIn("packets.map(\\.count)", read)
        self.assertIn("self.fail(BoringTunError.packetFlowReadFailed)", read)
        self.assertIn("if packets.isEmpty {", read)
        self.assertIn("IPPacketEnvelope.isValid(packet, family: family)", read)

    def test_real_swift_and_native_tests_remain_required(self):
        self.assertIn("Shared/WireGuardPacketReadBatchPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/wireguard_packet_read_batch_smoke.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("Tuist + macOS companion build", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
