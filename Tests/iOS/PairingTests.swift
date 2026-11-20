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

    func testRoutingPolicies() {
        XCTAssertEqual(RouteMode.split.allowedIPs, ["10.8.0.0/24"])
        XCTAssertEqual(RouteMode.full.allowedIPs, ["0.0.0.0/0", "::/0"])
    }
}
