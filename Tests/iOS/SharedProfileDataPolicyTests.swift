import Foundation
import XCTest
@testable import AgentApp

final class SharedProfileDataPolicyTests: XCTestCase {
    func testBoundarySizesForPublicAppGroupProfile() {
        XCTAssertFalse(SharedProfileDataPolicy.accepts(Data()))
        XCTAssertTrue(SharedProfileDataPolicy.accepts(Data(count: 1)))
        XCTAssertTrue(SharedProfileDataPolicy.accepts(Data(count: 4_096)))
        XCTAssertFalse(SharedProfileDataPolicy.accepts(Data(count: 4_097)))
    }

    func testInvalidAndExtremeLengthsAreRejected() {
        for count in [-1, 0, 4_097, Int.max] {
            XCTAssertFalse(SharedProfileDataPolicy.acceptsEncodedByteCount(count))
        }
        XCTAssertEqual(SharedProfileDataPolicy.maxEncodedBytes, 4_096)
    }

    func testPublicProfileCanonicalEncodingFitsLimit() throws {
        let sample = ServerProfile(
            publicKey: Data(repeating: 0x2A, count: 32).base64EncodedString(),
            endpoint: "home.example.net:51820"
        )
        let encoded = try JSONEncoder().encode(sample.validated())
        XCTAssertTrue(SharedProfileDataPolicy.accepts(encoded))
    }
}
