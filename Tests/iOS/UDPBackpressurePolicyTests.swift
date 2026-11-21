import XCTest
@testable import AgentApp

final class UDPBackpressurePolicyTests: XCTestCase {
    func testEnqueuesOnlyBelowCapacity() {
        for pending in [0, 1, 128, 255] {
            XCTAssertEqual(UDPBackpressurePolicy.decision(
                pendingSends: pending, maxPendingSends: 256
            ), .enqueue)
        }
    }

    func testFullQueueDropsRatherThanFailures() {
        XCTAssertEqual(UDPBackpressurePolicy.decision(
            pendingSends: 256, maxPendingSends: 256
        ), .drop)
        XCTAssertEqual(UDPBackpressurePolicy.decision(
            pendingSends: 1, maxPendingSends: 1
        ), .drop)
    }

    func testCorruptAccountingIsInvalid() {
        for pending in [-1, 257, Int.max] {
            XCTAssertEqual(UDPBackpressurePolicy.decision(
                pendingSends: pending, maxPendingSends: 256
            ), .invalid)
        }
        for limit in [0, -1] {
            XCTAssertEqual(UDPBackpressurePolicy.decision(
                pendingSends: 0, maxPendingSends: limit
            ), .invalid)
        }
    }
}
