import Foundation
import XCTest
@testable import AgentApp

final class UniqueFlatJSONObjectPolicyTests: XCTestCase {
    func testRealMacQRAndDuplicateMemberRejection() throws {
        let key = Data(repeating: 0x2A, count: 32).base64EncodedString()
        let valid = try PairingQRCode(
            kind: .mac, publicKey: key, endpoint: "home.example.test:51820"
        ).encodedText()
        XCTAssertTrue(UniqueFlatJSONObjectPolicy.hasUniqueStringKeys(Data(valid.utf8)))
        XCTAssertNoThrow(try PairingQRCode.decodeMac(valid))
        for suffix in [
            #","endpoint":"evil.example.test:51820"}"#,
            #","endp\u006fint":"evil.example.test:51820"}"#,
            #","publicKey":"not-a-key"}"#,
            #","publi\u0063Key":"not-a-key"}"#
        ] {
            let duplicate = String(valid.dropLast()) + suffix
            XCTAssertFalse(UniqueFlatJSONObjectPolicy.hasUniqueStringKeys(Data(duplicate.utf8)))
            XCTAssertThrowsError(try PairingQRCode.decodeMac(duplicate))
        }
    }

    func testFlatObjectOnlyAndStrictEndOfInput() {
        for invalid in [
            Data(),
            Data("{}".utf8),
            Data("[]".utf8),
            Data(#"{"kind":{"nested":"mac"}}"#.utf8),
            Data(#"{"kind":"mac",}"#.utf8),
            Data(#"{"kind":"mac"}trailing"#.utf8),
            Data(#"{"kind":"mac""#.utf8)
        ] {
            XCTAssertFalse(UniqueFlatJSONObjectPolicy.hasUniqueStringKeys(invalid))
        }
    }
}
