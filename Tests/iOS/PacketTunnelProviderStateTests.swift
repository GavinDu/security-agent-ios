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
