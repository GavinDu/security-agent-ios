import XCTest
@testable import AgentApp

final class WireGuardPathWaitGenerationTests: XCTestCase {
    func testAuthenticatedWaitEpisodeIsSingleFlightAndStaleSafe() {
        var state = WireGuardPathWaitGeneration()
        let token = state.beginWait()!
        XCTAssertTrue(state.accepts(token))
        XCTAssertNil(state.beginWait())
        XCTAssertFalse(state.permitsEngineIO)
        XCTAssertTrue(state.requiresFreshStartOnReady)
        XCTAssertNil(state.beginWait()) // repeated waiting cannot extend deadline
        state.invalidate() // terminal teardown only after ready or timeout
        XCTAssertTrue(state.permitsEngineIO)
        XCTAssertFalse(state.requiresFreshStartOnReady)
        XCTAssertFalse(state.accepts(token))
        let next = state.beginWait()!
        XCTAssertNotEqual(token, next)
        XCTAssertTrue(state.accepts(next))
        XCTAssertFalse(state.accepts(token))
        state.invalidate()
        XCTAssertFalse(state.accepts(next))
    }
}
