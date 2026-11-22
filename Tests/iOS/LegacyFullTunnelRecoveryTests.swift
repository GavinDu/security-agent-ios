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

    func testOrphanedNativeVPNFailsClosedWithoutPairingProfile() {
        for active in [false, true] {
            for onDemand in [false, true] {
                let decision = LegacyFullTunnelRecovery.assess(
                    isFullMode: nil, isActive: active, isOnDemandEnabled: onDemand
                )
                XCTAssertEqual(decision, .init(
                    stopActiveSession: active,
                    disableOnDemand: onDemand,
                    blockNewConnection: true
                ))
            }
        }
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
