import Foundation
import XCTest
@testable import AgentApp

final class VPNPrivateChatAccessTests: XCTestCase {
    private func permits(
        observed: Bool = true,
        native: Bool = true,
        inventory: Bool = true,
        split: Bool = true,
        bound: Bool = true,
        noWrite: Bool = true
    ) -> Bool {
        VPNPrivateChatAccessPolicy.permitsAccess(
            observedConnected: observed,
            nativeConnected: native,
            trustedNativeInventory: inventory,
            verifiedSplitProfile: split,
            nativeProfileBound: bound,
            noPreferenceWriteInFlight: noWrite
        )
    }

    func testConnectedStatusAloneCannotAuthorizePrivateWebKit() {
        XCTAssertTrue(permits())
        XCTAssertFalse(permits(observed: false))
        XCTAssertFalse(permits(native: false))
        XCTAssertFalse(permits(inventory: false))
        XCTAssertFalse(permits(split: false))
        XCTAssertFalse(permits(bound: false))
        XCTAssertFalse(permits(noWrite: false))
    }

    func testExistingNativeProfileDigestIsStillSingleSourceOfTruth() throws {
        let profile = ServerProfile(
            publicKey: Data(repeating: 0x45, count: 32).base64EncodedString(),
            endpoint: "home.example.org:51820"
        )
        let digest = try profile.publicProfileDigest()
        let metadata = NativeProfileBindingPolicy.metadata(for: digest)
        XCTAssertTrue(NativeProfileBindingPolicy.allowsStart(
            metadata: metadata, profileDigest: digest
        ))
        let changed = ServerProfile(
            publicKey: profile.publicKey, endpoint: "other.example.org:51820"
        )
        XCTAssertFalse(NativeProfileBindingPolicy.allowsStart(
            metadata: metadata, profileDigest: try changed.publicProfileDigest()
        ))
        XCTAssertFalse(permits(bound: false))
        XCTAssertFalse(NativeProfileBindingPolicy.allowsStart(
            metadata: nil, profileDigest: digest
        ))
        XCTAssertFalse(permits(inventory: false))
    }
}
