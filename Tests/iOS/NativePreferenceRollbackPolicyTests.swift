import XCTest
@testable import AgentApp

final class NativePreferenceRollbackPolicyTests: XCTestCase {
    func testCaptureRejectsUnsafeOrUnverifiedPriorAndOnDemand() {
        for mask in 0..<128 {
            func flag(_ bit: Int) -> Bool { mask & (1 << bit) != 0 }
            XCTAssertEqual(NativePreferenceRollbackPolicy.canCapture(
                priorVerified: flag(0), persistedPrior: flag(1),
                priorSplit: flag(2), attemptedSplit: flag(3),
                priorOnDemand: flag(4), attemptedOnDemand: flag(5),
                differentProfiles: flag(6)), mask == 79)
        }
    }
    func testRestoreOnlyExactAttemptWhileDisconnectedAndPriorStillPersisted() {
        for mask in 0..<32 {
            func flag(_ bit: Int) -> Bool { mask & (1 << bit) != 0 }
            let expected: NativePreferenceRollbackPolicy.Decision =
                !flag(0) || !flag(1) ? .manualRepair :
                flag(3) ? .unchanged :
                flag(2) && flag(4) ? .restore : .manualRepair
            XCTAssertEqual(NativePreferenceRollbackPolicy.decide(
                persistedPrior: flag(0), trustedInventory: flag(1),
                nativeDisconnected: flag(2), nativeMatchesPrior: flag(3),
                nativeMatchesAttempted: flag(4)), expected)
        }
    }
}
