import Foundation
import XCTest
@testable import AgentApp

final class NativeProfileBindingTests: XCTestCase {
    private let key = Data(repeating: 0x2a, count: 32).base64EncodedString()

    func testCanonicalPublicDigestIsStableAcrossEncodeDecode() throws {
        let original = ServerProfile(publicKey: key, endpoint: "home.example.org:51820")
        let digest = try original.publicProfileDigest()
        let decoded = try JSONDecoder().decode(
            ServerProfile.self, from: JSONEncoder().encode(original)
        )
        XCTAssertEqual(digest, try decoded.publicProfileDigest())
        XCTAssertEqual(Data(base64Encoded: digest)?.count, 32)
        XCTAssertTrue(NativeProfileBindingPolicy.allowsStart(
            metadata: NativeProfileBindingPolicy.metadata(for: digest),
            profileDigest: digest
        ))
    }

    func testDifferentPublicPeerRoutingAndOnDemandChangeDigest() throws {
        let original = ServerProfile(publicKey: key, endpoint: "home.example.org:51820")
        let digest = try original.publicProfileDigest()
        let otherPeer = ServerProfile(
            publicKey: Data(repeating: 0x2b, count: 32).base64EncodedString(),
            endpoint: original.endpoint
        )
        let otherEndpoint = ServerProfile(publicKey: key, endpoint: "other.example.org:51820")
        var fullRoute = original
        fullRoute.routeMode = .full
        var onDemand = original
        onDemand.onDemand = true

        for changed in [otherPeer, otherEndpoint, fullRoute, onDemand] {
            let changedDigest = try changed.publicProfileDigest()
            XCTAssertNotEqual(changedDigest, digest)
            XCTAssertFalse(NativeProfileBindingPolicy.allowsStart(
                metadata: NativeProfileBindingPolicy.metadata(for: digest),
                profileDigest: changedDigest
            ))
        }
    }

    func testLegacyMissingCorruptOrMismatchedNativeMetadataFailsClosed() throws {
        let digest = try ServerProfile(
            publicKey: key, endpoint: "home.example.org:51820"
        ).publicProfileDigest()
        XCTAssertFalse(NativeProfileBindingPolicy.allowsStart(
            metadata: ["profileVersion": 1], profileDigest: digest
        ))
        XCTAssertFalse(NativeProfileBindingPolicy.allowsStart(
            metadata: ["profileVersion": 2, "publicProfileDigest": "wrong"], profileDigest: digest
        ))
        XCTAssertFalse(NativeProfileBindingPolicy.allowsStart(
            metadata: nil, profileDigest: digest
        ))
        XCTAssertFalse(NativeProfileBindingPolicy.allowsStart(
            metadata: NativeProfileBindingPolicy.metadata(for: digest),
            profileDigest: nil
        ))
    }
}
