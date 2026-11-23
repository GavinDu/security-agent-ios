import XCTest
@testable import AgentApp

final class BoringTunFFIDonePolicyTests: XCTestCase {
    func testValidDoneHasExactlyZeroSize() {
        XCTAssertTrue(BoringTunFFIDonePolicy.acceptsDoneSize(0))
    }

    func testMalformedDoneSizesAreAlwaysRejected() {
        for malformed in [UInt(1), 148, 65_600, UInt.max] {
            XCTAssertFalse(BoringTunFFIDonePolicy.acceptsDoneSize(malformed))
        }
    }
}
