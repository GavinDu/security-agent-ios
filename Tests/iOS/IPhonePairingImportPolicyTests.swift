import Foundation
import XCTest
@testable import AgentApp

final class IPhonePairingImportPolicyTests: XCTestCase {
    private let key = Data(repeating: 0x2a, count: 32).base64EncodedString()

    func testValidIPhoneQrAndManualPublicKeyAreAccepted() throws {
        let text = #"{"kind":"iphone","publicKey":""# + key + #"","version":1}"#
        XCTAssertEqual(IPhonePairingImportPolicy.decodePublicKey(from: text), key)
        XCTAssertEqual(IPhonePairingImportPolicy.validatedPublicKey(key), key)
    }

    func testWrongVersionTypeExtraEndpointAndTruncatedKeyRejected() throws {
        let valid = #"{"kind":"iphone","publicKey":""# + key + #"","version":1}"#
        XCTAssertNil(IPhonePairingImportPolicy.decodePublicKey(
            from: valid.replacingOccurrences(of: "iphone", with: "mac")
        ))
        XCTAssertNil(IPhonePairingImportPolicy.decodePublicKey(
            from: valid.replacingOccurrences(of: #""version":1"#, with: #""version":2"#)
        ))
        XCTAssertNil(IPhonePairingImportPolicy.decodePublicKey(
            from: valid.replacingOccurrences(of: #""version":1"#,
                                            with: #""endpoint":"evil.test","version":1"#)
        ))
        for suffix in [
            #","endpoint":null}"#,
            #","endpoint":"evil.test:51820"}"#,
            #","publicKey":"bad"}"#,
            #","publi\u0063Key":"bad"}"#
        ] {
            XCTAssertNil(IPhonePairingImportPolicy.decodePublicKey(
                from: String(valid.dropLast()) + suffix
            ))
        }
        XCTAssertNil(IPhonePairingImportPolicy.validatedPublicKey("bad"))
        XCTAssertNil(IPhonePairingImportPolicy.validatedPublicKey(
            Data(repeating: 0, count: 32).base64EncodedString()
        ))
        XCTAssertNil(IPhonePairingImportPolicy.decodePublicKey(
            from: String(repeating: "x", count: 4097)
        ))
    }
}
