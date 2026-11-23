import XCTest
@testable import AgentApp

final class WireGuardPacketReadBatchPolicyTests: XCTestCase {
    func testEmptyAndMatchingNativeUtunBatchesAreAllowed() {
        XCTAssertTrue(WireGuardPacketReadBatchPolicy.accepts(packetCount: 0, protocolCount: 0))
        XCTAssertTrue(WireGuardPacketReadBatchPolicy.accepts(packetCount: 1, protocolCount: 1))
        XCTAssertTrue(WireGuardPacketReadBatchPolicy.accepts(packetCount: 64, protocolCount: 64))
    }

    func testMismatchesAndImpossibleNegativeCountsFailClosed() {
        for (packets, protocols) in [(0, 1), (1, 0), (1, 2), (2, 1), (-1, -1)] {
            XCTAssertFalse(
                WireGuardPacketReadBatchPolicy.accepts(
                    packetCount: packets, protocolCount: protocols
                )
            )
        }
        XCTAssertFalse(
            WireGuardPacketReadBatchPolicy.accepts(
                packetCount: Int.max, protocolCount: Int.max - 1
            )
        )
    }
}
