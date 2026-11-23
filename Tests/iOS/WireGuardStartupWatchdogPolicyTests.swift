import XCTest
@testable import AgentApp

final class WireGuardStartupWatchdogPolicyTests: XCTestCase {
    func testOverallStartupBoundAndGenerationGuards() {
        let shouldExpire = WireGuardStartupWatchdogPolicy.shouldExpire
        XCTAssertEqual(WireGuardStartupWatchdogPolicy.timeoutSeconds, 30)
        XCTAssertTrue(shouldExpire(true, true, 1, 1))
        XCTAssertFalse(shouldExpire(false, true, 1, 1))
        XCTAssertFalse(shouldExpire(true, false, 1, 1))
        XCTAssertFalse(shouldExpire(true, true, 0, 0))
        XCTAssertFalse(shouldExpire(true, true, 1, 2))
        XCTAssertTrue(shouldExpire(true, true, UInt64.max, UInt64.max))
    }
}
