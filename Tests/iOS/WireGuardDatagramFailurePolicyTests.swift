import XCTest
@testable import AgentApp

final class WireGuardDatagramFailurePolicyTests: XCTestCase {
    func testRemoteAuthenticationAndSizeRejectionDoesNotTearDownVPN() {
        XCTAssertEqual(WireGuardDatagramFailurePolicy.disposition(
            for: .authenticationRejected
        ), .discard)
        XCTAssertEqual(WireGuardDatagramFailurePolicy.disposition(
            for: .malformedIncomingPacket
        ), .discard)
    }

    func testMalformedRustFFIAndUnexpectedLocalFailureTearDownVPN() {
        XCTAssertEqual(WireGuardDatagramFailurePolicy.disposition(
            for: .malformedFFIResponse
        ), .stopTunnel)
        XCTAssertEqual(WireGuardDatagramFailurePolicy.disposition(
            for: .unexpectedLocalFailure
        ), .stopTunnel)
    }
}
