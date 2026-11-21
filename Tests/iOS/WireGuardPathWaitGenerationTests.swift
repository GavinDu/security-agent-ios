import XCTest
@testable import AgentApp

final class WireGuardPathWaitGenerationTests: XCTestCase {
    func testAuthenticatedWaitEpisodeIsSingleFlightAndStaleSafe() {
        var state = WireGuardPathWaitGeneration()
        let token = state.beginWait()!
        XCTAssertTrue(state.accepts(token))
        XCTAssertNil(state.beginWait())
        state.invalidate() // NWConnection.ready or stop
        XCTAssertFalse(state.accepts(token))
        let next = state.beginWait()!
        XCTAssertNotEqual(token, next)
        XCTAssertTrue(state.accepts(next))
        XCTAssertFalse(state.accepts(token))
        state.invalidate()
        XCTAssertFalse(state.accepts(next))
    }
}
