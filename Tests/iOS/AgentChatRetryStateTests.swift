import XCTest
@testable import AgentApp

final class AgentChatRetryStateTests: XCTestCase {
    func testRetryRestartsChatAndIgnoresOldGenerationEvents() {
        var state = AgentChatRetryState()
        let old = state.generation
        XCTAssertTrue(state.reportLoadResult(unreachable: true, generation: old))
        XCTAssertTrue(state.isUnavailable)

        state.retry()
        XCTAssertNotEqual(state.generation, old)
        XCTAssertFalse(state.isUnavailable)
        XCTAssertFalse(state.reportLoadResult(unreachable: true, generation: old))
        XCTAssertFalse(state.isUnavailable)

        let current = state.generation
        XCTAssertTrue(state.reportLoadResult(unreachable: true, generation: current))
        XCTAssertTrue(state.isUnavailable)
        XCTAssertFalse(state.reportLoadResult(unreachable: false, generation: old))
        XCTAssertTrue(state.isUnavailable)
    }

    func testVPNTransitionInvalidatesPreviousPageAndOverlay() {
        var state = AgentChatRetryState()
        let initial = state.generation
        XCTAssertTrue(state.reportLoadResult(unreachable: true, generation: initial))
        state.resetForVPNStatusChange()
        XCTAssertNotEqual(state.generation, initial)
        XCTAssertFalse(state.isUnavailable)
        XCTAssertFalse(state.reportLoadResult(unreachable: true, generation: initial))
        XCTAssertFalse(state.isUnavailable)
    }
}
