import Foundation
import XCTest
@testable import AgentApp

final class WireGuardReadProtocolPolicyTests: XCTestCase {
    private func accepts(_ value: NSNumber) -> Bool {
        WireGuardReadProtocolPolicy.accepts(value, ipv4: 2, ipv6: 30)
    }

    func testOnlySupportedAddressFamiliesPassWithoutNarrowing() {
        XCTAssertTrue(accepts(NSNumber(value: Int32(2))))
        XCTAssertTrue(accepts(NSNumber(value: Int32(30))))
        for candidate in [Int32(0), Int32(-1), Int32(1), Int32(31)] {
            XCTAssertFalse(accepts(NSNumber(value: candidate)))
        }
    }

    func testLargeNSNumberCannotMasqueradeAsAFInetOrAFInet6() {
        XCTAssertFalse(accepts(NSNumber(value: UInt64(4_294_967_298))))
        XCTAssertFalse(accepts(NSNumber(value: UInt64(4_294_967_326))))
        XCTAssertFalse(accepts(NSNumber(value: UInt64.max)))
        XCTAssertFalse(accepts(NSNumber(value: Double(2.5))))
    }
}
