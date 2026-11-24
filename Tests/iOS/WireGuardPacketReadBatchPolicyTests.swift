import XCTest
@testable import AgentApp

final class WireGuardPacketReadBatchPolicyTests: XCTestCase {
    func testEmptyAndMatchingNativeUtunBatchesAreAllowed() {
        XCTAssertTrue(WireGuardPacketReadBatchPolicy.accepts(packetCount: 0, protocolCount: 0))
        XCTAssertTrue(WireGuardPacketReadBatchPolicy.accepts(packetCount: 1, protocolCount: 1))
        XCTAssertTrue(WireGuardPacketReadBatchPolicy.accepts(packetCount: 64, protocolCount: 64))
        XCTAssertTrue(WireGuardPacketReadBatchPolicy.accepts(packetCount: 256, protocolCount: 256))
        XCTAssertTrue(WireGuardPacketReadBatchPolicy.acceptsPayloadLengths([]))
        XCTAssertTrue(WireGuardPacketReadBatchPolicy.acceptsPayloadLengths(
            Array(repeating: 65_536, count: 128)
        ))
    }

    func testMismatchesAndImpossibleNegativeCountsFailClosed() {
        for (packets, protocols) in [(0, 1), (1, 0), (1, 2), (2, 1), (-1, -1),
                                      (257, 257), (Int.max, Int.max)] {
            XCTAssertFalse(
                WireGuardPacketReadBatchPolicy.accepts(
                    packetCount: packets, protocolCount: protocols
                )
            )
        }
    }

    func testPayloadBudgetRejectsLocalOversizeAndOverflow() {
        XCTAssertEqual(WireGuardPacketReadBatchPolicy.maxPacketBytes, IPPacketEnvelope.maxInnerBytes)
        XCTAssertTrue(WireGuardPacketReadBatchPolicy.acceptsPayloadLengths([IPPacketEnvelope.maxInnerBytes]))
        XCTAssertFalse(WireGuardPacketReadBatchPolicy.acceptsPayloadLengths([IPPacketEnvelope.maxInnerBytes + 1]))
        XCTAssertTrue(WireGuardPacketReadBatchPolicy.acceptsPayloadLengths(
            Array(repeating: 1420, count: 256)
        ))
        for lengths in [
            [0], [-1], [65_537], [Int.max], [1, Int.max],
            Array(repeating: 65_536, count: 129),
            Array(repeating: 1, count: 257)
        ] {
            XCTAssertFalse(WireGuardPacketReadBatchPolicy.acceptsPayloadLengths(lengths))
        }
    }
}
