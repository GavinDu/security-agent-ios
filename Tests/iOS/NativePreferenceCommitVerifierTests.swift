import Foundation
import XCTest
@testable import AgentApp

final class NativePreferenceCommitVerifierTests: XCTestCase {
    private let bundleID = AgentConstants.tunnelBundleID
    private let endpoint = "home.example.org:51820"
    private let digest = Data(repeating: 0x39, count: 32).base64EncodedString()

    private func snapshot(
        providerID: String? = AgentConstants.tunnelBundleID,
        endpoint: String? = "home.example.org:51820",
        digest: String? = nil,
        enabled: Bool = true,
        onDemand: Bool = false,
        ruleCount: Int = 0,
        usesConnectRule: Bool = false
    ) -> NativePreferenceCommitSnapshot {
        NativePreferenceCommitSnapshot(
            providerBundleIdentifier: providerID,
            serverAddress: endpoint,
            metadata: NativeProfileBindingPolicy.metadata(for: digest ?? self.digest),
            isEnabled: enabled,
            isOnDemandEnabled: onDemand,
            onDemandRuleCount: ruleCount,
            onDemandUsesConnectRule: usesConnectRule
        )
    }

    private func permits(_ candidate: NativePreferenceCommitSnapshot,
                         expectedDemand: Bool = false) -> Bool {
        NativePreferenceCommitVerifier.matches(
            candidate,
            expectedBundleID: bundleID,
            expectedServerAddress: endpoint,
            expectedProfileDigest: digest,
            expectedOnDemand: expectedDemand
        )
    }

    func testFreshlyReloadedNativeProfileMatchesBeforePublicCommit() {
        XCTAssertTrue(permits(snapshot()))
        XCTAssertTrue(permits(snapshot(
            onDemand: true, ruleCount: 1, usesConnectRule: true
        ), expectedDemand: true))
    }

    func testWrongProviderEndpointDigestOrDisabledNativeProfileCannotCommit() {
        XCTAssertFalse(permits(snapshot(providerID: "other.bundle")))
        XCTAssertFalse(permits(snapshot(endpoint: "changed.example.org:51820")))
        XCTAssertFalse(permits(snapshot(
            digest: Data(repeating: 0x55, count: 32).base64EncodedString()
        )))
        XCTAssertFalse(permits(snapshot(enabled: false)))
        XCTAssertFalse(permits(snapshot(providerID: nil)))
        XCTAssertFalse(permits(snapshot(endpoint: nil)))
    }

    func testNativeOnDemandDivergenceCannotCommit() {
        XCTAssertFalse(permits(snapshot(onDemand: true, ruleCount: 1)))
        XCTAssertFalse(permits(snapshot(ruleCount: 1)))
        XCTAssertFalse(permits(snapshot(onDemand: true, ruleCount: 1), expectedDemand: true))
        XCTAssertFalse(permits(snapshot(onDemand: true, ruleCount: 0), expectedDemand: true))
        XCTAssertFalse(permits(snapshot(onDemand: true, ruleCount: 2), expectedDemand: true))
        XCTAssertFalse(permits(snapshot(), expectedDemand: true))
    }

    func testMissingLegacyNativeMetadataCannotCommit() {
        let legacy = NativePreferenceCommitSnapshot(
            providerBundleIdentifier: bundleID,
            serverAddress: endpoint,
            metadata: ["profileVersion": 1],
            isEnabled: true,
            isOnDemandEnabled: false,
            onDemandRuleCount: 0,
            onDemandUsesConnectRule: false
        )
        XCTAssertFalse(permits(legacy))
    }
}
