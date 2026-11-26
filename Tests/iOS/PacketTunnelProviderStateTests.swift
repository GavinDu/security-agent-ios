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

    func testProductionOwnershipStopBeforeStartAndRejectsStaleEngine() {
        final class Engine {}
        enum Failure: Error { case stopped }
        var ownership = PacketTunnelProviderOwnership<Engine>()
        var starts = [String]()
        var stops = 0
        let old = Engine()
        let next = Engine()
        let first = PacketTunnelOneShot<Error?> { error in
            starts.append(error == nil ? "success" : "stopped")
        }
        XCTAssertTrue(ownership.beginStart(first))
        ownership.installEngine(old)
        XCTAssertTrue(ownership.beginStop { stops += 1 })
        XCTAssertFalse(ownership.beginStop { stops += 1 })
        XCTAssertFalse(ownership.finishStart(for: old, success: true))
        XCTAssertTrue(ownership.takeStopCallbacks().stops.isEmpty)
        XCTAssertTrue(ownership.finishStop(for: old))
        let callbacks = ownership.takeStopCallbacks()
        callbacks.start?.call(Failure.stopped)
        callbacks.stops.forEach { $0() }
        first.call(nil) // delayed or duplicate transport start
        XCTAssertEqual(starts, ["stopped"])
        XCTAssertEqual(stops, 2)
        let second = PacketTunnelOneShot<Error?> { error in
            starts.append(error == nil ? "success" : "stopped")
        }
        XCTAssertTrue(ownership.beginStart(second))
        ownership.installEngine(next)
        XCTAssertFalse(ownership.finishStart(for: old, success: false))
        XCTAssertTrue(ownership.finishStart(for: next, success: true))
        second.call(nil)
        XCTAssertTrue(ownership.beginStop { stops += 1 })
        XCTAssertFalse(ownership.finishStop(for: old))
        XCTAssertTrue(ownership.takeStopCallbacks().stops.isEmpty)
        XCTAssertTrue(ownership.finishStop(for: next))
        let finished = ownership.takeStopCallbacks()
        XCTAssertNil(finished.start)
        finished.stops.forEach { $0() }
        XCTAssertEqual(starts, ["stopped", "success"])
        XCTAssertEqual(stops, 3)
        XCTAssertEqual(ownership.phase, .idle)
    }

    func testProductionOwnershipPreparationAndTransportFailuresAreRecoverable() {
        final class Engine {}
        enum Failure: Error { case denied, handshake }
        var ownership = PacketTunnelProviderOwnership<Engine>()
        var failures = 0
        let denied = PacketTunnelOneShot<Error?> { if $0 != nil { failures += 1 } }
        XCTAssertTrue(ownership.beginStart(denied))
        XCTAssertFalse(ownership.beginStart(PacketTunnelOneShot<Error?> { _ in XCTFail() }))
        ownership.failPreparation()
        denied.call(Failure.denied)
        XCTAssertEqual(ownership.phase, .idle)
        XCTAssertNil(ownership.engine)
        let engine = Engine()
        let failed = PacketTunnelOneShot<Error?> { if $0 != nil { failures += 1 } }
        XCTAssertTrue(ownership.beginStart(failed))
        ownership.installEngine(engine)
        XCTAssertTrue(ownership.finishStart(for: engine, success: false))
        failed.call(Failure.handshake)
        XCTAssertNil(ownership.engine)
        XCTAssertEqual(ownership.phase, .idle)
        XCTAssertEqual(failures, 2)
        var idleStops = 0
        XCTAssertFalse(ownership.beginStop { idleStops += 1 })
        ownership.takeStopCallbacks().stops.forEach { $0() }
        XCTAssertEqual(idleStops, 1)
        XCTAssertTrue(ownership.takeStopCallbacks().stops.isEmpty)
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
