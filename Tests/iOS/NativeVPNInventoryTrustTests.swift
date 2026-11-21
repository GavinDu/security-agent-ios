import XCTest
@testable import AgentApp

final class NativeVPNInventoryTrustTests: XCTestCase {
    func testInitialAndFailedNativeReadsNeverPermitWrites() {
        var trust = NativeVPNInventoryTrust()
        XCTAssertFalse(trust.permitsMutation)
        trust.beginLoad()
        XCTAssertFalse(trust.permitsMutation)
        trust.didFailLoad()
        XCTAssertEqual(trust.state, .failed)
        XCTAssertFalse(trust.permitsMutation)
        trust.didCommitVerifiedWrite()
        XCTAssertFalse(trust.permitsMutation)
    }

    func testSubsequentLoadFailureRevokesPreviouslyConfirmedInventory() {
        var trust = NativeVPNInventoryTrust()
        trust.beginLoad()
        trust.didLoadUniqueInventory()
        XCTAssertTrue(trust.permitsMutation)
        trust.beginLoad()
        trust.didFailLoad()
        XCTAssertFalse(trust.permitsMutation)
        trust.beginLoad()
        trust.didLoadUniqueInventory()
        XCTAssertTrue(trust.permitsMutation)
    }

    func testDuplicateAndInterruptedNativeMutationRemainBlocked() {
        var trust = NativeVPNInventoryTrust()
        trust.beginLoad()
        trust.didLoadDuplicateInventory()
        XCTAssertEqual(trust.state, .ambiguous)
        XCTAssertFalse(trust.permitsMutation)
        trust.didLoadUniqueInventory() // invalid late callback
        XCTAssertFalse(trust.permitsMutation)
        trust.beginLoad()
        trust.didLoadUniqueInventory()
        XCTAssertTrue(trust.permitsMutation)
        trust.beginWrite()
        XCTAssertFalse(trust.permitsMutation)
        trust.didFailLoad() // out-of-phase old failure
        XCTAssertEqual(trust.state, .unverified)
        trust.didCommitVerifiedWrite()
        XCTAssertTrue(trust.permitsMutation)
    }

    func testObsoleteNativeReloadDoesNotRestoreTrust() {
        var gate = NativePreferenceReloadGate()
        var trust = NativeVPNInventoryTrust()
        let old = gate.begin()
        trust.beginLoad()
        let current = gate.begin()
        trust.beginLoad()
        XCTAssertEqual(gate.disposition(
            for: old, writeInFlight: false, loadSucceeded: true
        ), .discard)
        XCTAssertFalse(trust.permitsMutation)
        XCTAssertEqual(gate.disposition(
            for: current, writeInFlight: false, loadSucceeded: true
        ), .publish)
        trust.didLoadUniqueInventory()
        XCTAssertTrue(trust.permitsMutation)
    }
}
