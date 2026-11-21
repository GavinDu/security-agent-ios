import XCTest
@testable import AgentApp

final class ProfileSaveSafetyPolicyTests: XCTestCase {
    func testFirstProvisioningPermittedOnlyAfterSeparateInventoryTrust() {
        XCTAssertTrue(ProfileSaveSafetyPolicy.permitsSave(
            hasInstalledManager: false, nativeDisconnected: false,
            nativeOnDemandEnabled: false, changesPeerOrRoutes: true,
            candidateOnDemand: false
        ))
    }

    func testAllActiveNativeStatesRejectProfileMutations() {
        for hasOnDemand in [false, true] {
            for changingPeer in [false, true] {
                for candidateOnDemand in [false, true] {
                    XCTAssertFalse(ProfileSaveSafetyPolicy.permitsSave(
                        hasInstalledManager: true, nativeDisconnected: false,
                        nativeOnDemandEnabled: hasOnDemand,
                        changesPeerOrRoutes: changingPeer,
                        candidateOnDemand: candidateOnDemand
                    ))
                }
            }
        }
    }

    func testDisconnectedManualRePairAllowed() {
        XCTAssertTrue(ProfileSaveSafetyPolicy.permitsSave(
            hasInstalledManager: true, nativeDisconnected: true,
            nativeOnDemandEnabled: false, changesPeerOrRoutes: true,
            candidateOnDemand: false
        ))
    }

    func testNativeOnDemandPermitsOnlyExistingProfileDisable() {
        XCTAssertTrue(ProfileSaveSafetyPolicy.permitsSave(
            hasInstalledManager: true, nativeDisconnected: true,
            nativeOnDemandEnabled: true, changesPeerOrRoutes: false,
            candidateOnDemand: false
        ))
        for changed in [false, true] {
            XCTAssertFalse(ProfileSaveSafetyPolicy.permitsSave(
                hasInstalledManager: true, nativeDisconnected: true,
                nativeOnDemandEnabled: true, changesPeerOrRoutes: changed,
                candidateOnDemand: true
            ))
        }
        XCTAssertFalse(ProfileSaveSafetyPolicy.permitsSave(
            hasInstalledManager: true, nativeDisconnected: true,
            nativeOnDemandEnabled: true, changesPeerOrRoutes: true,
            candidateOnDemand: false
        ))
    }
}
