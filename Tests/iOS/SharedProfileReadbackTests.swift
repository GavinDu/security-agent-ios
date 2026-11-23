import Foundation
import XCTest
@testable import AgentApp

final class SharedProfileReadbackTests: XCTestCase {
    func testMatchingAndChangedPublicProfileBytes() {
        let expected = Data("{\"publicKey\":\"public\"}".utf8)
        XCTAssertTrue(SharedProfileReadbackPolicy.accepts(
            expected: expected, observed: expected
        ))
        XCTAssertFalse(SharedProfileReadbackPolicy.accepts(
            expected: expected, observed: nil
        ))
        XCTAssertFalse(SharedProfileReadbackPolicy.accepts(
            expected: expected, observed: Data("{\"publicKey\":\"changed\"}".utf8)
        ))
    }

    func testBoundsAreReappliedToReadback() {
        XCTAssertFalse(SharedProfileReadbackPolicy.accepts(
            expected: Data(), observed: Data()
        ))
        let max = Data(repeating: 0x31, count: SharedProfileDataPolicy.maxEncodedBytes)
        XCTAssertTrue(SharedProfileReadbackPolicy.accepts(expected: max, observed: max))
        XCTAssertFalse(SharedProfileReadbackPolicy.accepts(
            expected: max, observed: Data(repeating: 0x31, count: max.count + 1)
        ))
    }
}
