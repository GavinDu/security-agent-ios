import XCTest
@testable import AgentApp

final class TunnelLifecycleGenerationTests: XCTestCase {
    func testStaleCallbacksAfterStopAndRestartAreRejected() {
        var generation = TunnelLifecycleGeneration()
        let first = generation.advance()
        XCTAssertTrue(generation.matches(first))
        generation.advance() // cancellation
        XCTAssertFalse(generation.matches(first))
        let second = generation.advance()
        XCTAssertFalse(generation.matches(first))
        XCTAssertTrue(generation.matches(second))
        XCTAssertFalse(generation.matches(0))
    }
}
