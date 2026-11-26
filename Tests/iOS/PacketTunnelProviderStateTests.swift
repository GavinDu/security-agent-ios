import Foundation
import XCTest
@testable import AgentApp

final class PacketTunnelProviderStateTests: XCTestCase {
    func testOverlappingStartAndStopAreRejected() {
        var state = PacketTunnelProviderState()
        XCTAssertTrue(state.beginStart())
        XCTAssertFalse(state.beginStart())
        XCTAssertTrue(state.beginStop())
        XCTAssertFalse(state.beginStop())
        XCTAssertFalse(state.finishStart(success: true))
        XCTAssertTrue(state.finishStop())
        XCTAssertEqual(state.phase, .idle)
    }

    func testOneShotRejectsDuplicateAndReentrantCompletion() {
        var results: [Int] = []
        var once: PacketTunnelOneShot<Int>!
        once = PacketTunnelOneShot { value in
            results.append(value)
            once.call(99)
        }
        once.call(1)
        once.call(2)
        XCTAssertEqual(results, [1])
    }

    func testOneShotConcurrentCallsDeliverExactlyOneResult() {
        let lock = NSLock()
        var count = 0
        let once = PacketTunnelOneShot<Int> { _ in
            lock.lock()
            count += 1
            lock.unlock()
        }
        DispatchQueue.concurrentPerform(iterations: 128) { once.call($0) }
        XCTAssertEqual(count, 1)
    }

    func testStartFailureAndRecovery() {
        var state = PacketTunnelProviderState()
        XCTAssertTrue(state.beginStart())
        XCTAssertTrue(state.finishStart(success: false))
        XCTAssertEqual(state.phase, .idle)
        XCTAssertTrue(state.beginStart())
        XCTAssertTrue(state.finishStart(success: true))
        XCTAssertEqual(state.phase, .connected)
    }
}
