import Foundation
import XCTest
@testable import AgentApp

final class WireGuardPrivateIdentityPolicyTests: XCTestCase {
    func testRejectsInvalidStoredKeyLengthsAndAllZeroKey() {
        XCTAssertFalse(WireGuardPrivateIdentityPolicy.accepts(Data()))
        XCTAssertFalse(WireGuardPrivateIdentityPolicy.accepts(Data(repeating: 1, count: 31)))
        XCTAssertFalse(WireGuardPrivateIdentityPolicy.accepts(Data(repeating: 0, count: 32)))
        XCTAssertFalse(WireGuardPrivateIdentityPolicy.accepts(Data(repeating: 1, count: 33)))
    }

    func testAcceptsNonzeroExactLengthAndSingleNonzeroByte() {
        XCTAssertTrue(WireGuardPrivateIdentityPolicy.accepts(Data(repeating: 0x5A, count: 32)))
        var oneByte = Data(repeating: 0, count: 32)
        oneByte[31] = 1
        XCTAssertTrue(WireGuardPrivateIdentityPolicy.accepts(oneByte))
    }
}
