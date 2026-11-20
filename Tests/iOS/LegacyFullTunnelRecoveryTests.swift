import XCTest
@testable import AgentApp

final class LegacyFullTunnelRecoveryTests: XCTestCase {
    func testSplitSessionsAreUnaffected() {
        let decision = LegacyFullTunnelRecovery.assess(
            isFullMode: false, isActive: true, isOnDemandEnabled: true
        )
        XCTAssertEqual(decision, .init(
            stopActiveSession: false, disableOnDemand: false,
            blockNewConnection: false
        ))
    }

    func testConnectedLegacyFullModeIsStoppedAndOnDemandDisabled() {
        let decision = LegacyFullTunnelRecovery.assess(
            isFullMode: true, isActive: true, isOnDemandEnabled: true
        )
        XCTAssertTrue(decision.stopActiveSession)
        XCTAssertTrue(decision.disableOnDemand)
        XCTAssertTrue(decision.blockNewConnection)
    }

    func testInactiveFullModeStillRejectsManualConnect() {
        let decision = LegacyFullTunnelRecovery.assess(
            isFullMode: true, isActive: false, isOnDemandEnabled: false
        )
        XCTAssertFalse(decision.stopActiveSession)
        XCTAssertFalse(decision.disableOnDemand)
        XCTAssertTrue(decision.blockNewConnection)
    }
}
