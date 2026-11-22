import XCTest
@testable import AgentApp

final class WireGuardReceiveRearmPolicyTests: XCTestCase {
    func testNoDataOrEmptyEncryptedUDPBacksOff() {
        XCTAssertTrue(WireGuardReceiveRearmPolicy.needsBackoff(receivedByteCount: nil))
        XCTAssertTrue(WireGuardReceiveRearmPolicy.needsBackoff(receivedByteCount: 0))
        XCTAssertTrue(WireGuardReceiveRearmPolicy.needsBackoff(receivedByteCount: -1))
        XCTAssertEqual(WireGuardReceiveRearmPolicy.emptyReceiveDelayMilliseconds, 25)
    }

    func testNonemptyEncryptedUDPContinuesImmediately() {
        for length in [1, 4, 32, 65600] {
            XCTAssertFalse(WireGuardReceiveRearmPolicy.needsBackoff(
                receivedByteCount: length
            ))
        }
    }
}
