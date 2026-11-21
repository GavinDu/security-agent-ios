import XCTest
@testable import AgentApp

final class PairingTests: XCTestCase {
    private let validKey = Data(repeating: 0x2a, count: 32).base64EncodedString()

    func testRoundTripPairingQRCode() throws {
        let encoded = try PairingQRCode(
            kind: .mac, publicKey: validKey, endpoint: "home.example.org:51820"
        ).encodedText()
        let decoded = try PairingQRCode.decodeMac(encoded)
        XCTAssertEqual(decoded.publicKey, validKey)
        XCTAssertEqual(decoded.endpoint, "home.example.org:51820")
        XCTAssertEqual(decoded.routeMode, .split)
    }

    func testRejectsPhoneQRCodeForMacPairing() throws {
        let payload = try PairingQRCode(kind: .iphone, publicKey: validKey).encodedText()
        XCTAssertThrowsError(try PairingQRCode.decodeMac(payload))
    }

    func testRejectsInvalidKeyAndEndpoint() {
        XCTAssertThrowsError(try ServerProfile(publicKey: "bad", endpoint: "host:51820").validated())
        XCTAssertThrowsError(try ServerProfile(publicKey: validKey, endpoint: "not-an-endpoint").validated())
        XCTAssertThrowsError(try ServerProfile(publicKey: validKey, endpoint: "host:0").validated())
    }

    func testSplitProfileRejectsLiteralUnderlayEndpointInsideItsOwnRoute() {
        for endpoint in ["10.8.0.0:51820", "10.8.0.1:51820",
                         "10.8.0.2:51820", "10.8.0.255:51820"] {
            XCTAssertThrowsError(
                try ServerProfile(publicKey: validKey, endpoint: endpoint).validated(),
                "Accepted self-routed UDP endpoint: \(endpoint)"
            )
        }
        XCTAssertNoThrow(
            try ServerProfile(publicKey: validKey, endpoint: "10.8.1.1:51820").validated()
        )
        XCTAssertNoThrow(
            try ServerProfile(publicKey: validKey, endpoint: "192.168.1.20:51820").validated()
        )
    }

    func testRoutingPolicies() {
        XCTAssertEqual(RouteMode.split.allowedIPs, ["10.8.0.0/24"])
        XCTAssertEqual(RouteMode.full.allowedIPs, ["0.0.0.0/0", "::/0"])
    }

    func testFingerprintIsStableAndChangesForAnotherMacKey() throws {
        let profile = ServerProfile(publicKey: validKey, endpoint: "home.example.org:51820")
        XCTAssertEqual(try profile.publicKeyFingerprint(),
                       "544E62CE-E8033709-E389E5B2-755343D0-D0FA8C48-50215CFB-6331717E-80D1AEA3")
        let anotherKey = Data(repeating: 0x2b, count: 32).base64EncodedString()
        let otherProfile = ServerProfile(publicKey: anotherKey, endpoint: "home.example.org:51820")
        XCTAssertNotEqual(try profile.publicKeyFingerprint(), try otherProfile.publicKeyFingerprint())
    }

    func testRejectsUnsupportedQrVersionAndMalformedJson() throws {
        let encoded = try PairingQRCode(
            kind: .mac, publicKey: validKey, endpoint: "home.example.org:51820"
        ).encodedText()
        XCTAssertThrowsError(try PairingQRCode.decodeMac(encoded.replacingOccurrences(
            of: "\"version\":1", with: "\"version\":999"
        )))
        XCTAssertThrowsError(try PairingQRCode.decodeMac("not json"))
    }
}
