import Foundation
import XCTest
@testable import AgentApp

final class RequiredPSKProfileTests: XCTestCase {
    private func key(_ n: UInt8) -> String { Data(repeating: n, count: 32).base64EncodedString() }

    func testVersionedDigestAndLegacyCompatibility() throws {
        let server = key(42), client = key(7)
        let old = ServerProfile(publicKey: server, endpoint: "home.example.org:51820")
        let legacyJSON = Data(("{\"publicKey\":\"" + server + "\",\"endpoint\":\"home.example.org:51820\",\"routeMode\":\"split\",\"onDemand\":false}").utf8)
        let decoded = try JSONDecoder().decode(ServerProfile.self, from: legacyJSON)
        XCTAssertEqual(decoded, old)
        XCTAssertEqual(old.nativeBindingVersion, 2)
        XCTAssertEqual(try old.publicProfileDigest(), try decoded.publicProfileDigest())
        var protected = old
        protected.requiredPSK = .init(transactionID: UUID(), clientPublicKey: client)
        let digest = try protected.publicProfileDigest()
        XCTAssertEqual(protected.nativeBindingVersion, 3)
        XCTAssertNotEqual(try old.publicProfileDigest(), digest)
        let metadata = NativeProfileBindingPolicy.metadata(for: digest, version: 3)
        XCTAssertTrue(NativeProfileBindingPolicy.allowsStart(metadata: metadata, profileDigest: digest, expectedVersion: 3))
        XCTAssertFalse(NativeProfileBindingPolicy.allowsStart(metadata: metadata, profileDigest: digest, expectedVersion: 2))
        XCTAssertFalse(NativeProfileBindingPolicy.allowsStart(metadata: NativeProfileBindingPolicy.metadata(for: digest), profileDigest: digest, expectedVersion: 3))
        let restored = try JSONDecoder().decode(ServerProfile.self, from: JSONEncoder().encode(protected))
        XCTAssertEqual(restored, protected)
        XCTAssertEqual(try restored.publicProfileDigest(), digest)
        protected.requiredPSK = .init(transactionID: UUID(), clientPublicKey: client)
        XCTAssertNotEqual(try protected.publicProfileDigest(), digest)
        protected.requiredPSK = .init(transactionID: UUID(), clientPublicKey: server)
        XCTAssertThrowsError(try protected.validated())
    }

    func testOrdinarySaveCannotClearIntroduceOrReplaceMarker() {
        let server = key(42)
        let marker = PeerPSKRequirement(transactionID: UUID(), clientPublicKey: key(7))
        let other = PeerPSKRequirement(transactionID: UUID(), clientPublicKey: key(7))
        func allows(_ prior: PeerPSKRequirement?, _ candidate: PeerPSKRequirement?,
                    native: Bool = true, verified: Bool = true, target: String? = nil) -> Bool {
            PeerPSKRequirement.permitsOrdinarySave(prior: prior, priorServer: server,
                candidate: candidate, candidateServer: target ?? server,
                nativeRequiresPSK: native, priorVerified: verified)
        }
        XCTAssertTrue(allows(nil, nil, native: false, verified: false))
        XCTAssertFalse(allows(nil, marker, native: false))
        XCTAssertFalse(allows(marker, nil))
        XCTAssertFalse(allows(marker, other))
        XCTAssertFalse(allows(nil, nil, verified: false))
        XCTAssertFalse(allows(marker, marker, verified: false))
        XCTAssertFalse(allows(marker, marker, target: key(43)))
        XCTAssertTrue(allows(marker, marker))
    }
}
