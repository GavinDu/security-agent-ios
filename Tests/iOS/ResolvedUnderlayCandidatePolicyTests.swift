import Foundation
import XCTest
@testable import AgentApp

final class ResolvedUnderlayCandidatePolicyTests: XCTestCase {
    private let routes = RouteMode.split.allowedIPs

    func testSelectsAlreadyResolvedSafeNumericCandidateWithoutDNS() {
        XCTAssertEqual(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
            ["203.0.113.42", "2001:db8::1"], includedIPv4CIDRs: routes
        ), "203.0.113.42")
        XCTAssertEqual(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
            ["2001:db8::1", "203.0.113.42"], includedIPv4CIDRs: routes
        ), "2001:db8::1")
        XCTAssertEqual(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
            ["fd00::42"], includedIPv4CIDRs: routes
        ), "fd00::42")
    }

    func testFailClosedForUnsafeMixedResolvedAnswers() {
        for hostile in ["10.8.0.1", "::ffff:10.8.0.1", "home.example.net",
                        "0x0a080001", "203.0.113.42:51820",
                        "203.0.113.42 ", "fe80::1%en0", "10.8.0.256"] {
            XCTAssertNil(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
                ["203.0.113.42", hostile], includedIPv4CIDRs: routes
            ), hostile)
        }
    }

    func testRejectsUnusableNumericUnderlayEndpoints() {
        for hostile in ["0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1",
                        "255.255.255.255", "::", "::1", "ff02::1", "fe80::1",
                        "::10.8.0.1",
                        "::ffff:127.0.0.1", "::ffff:169.254.1.1"] {
            XCTAssertNil(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
                [hostile], includedIPv4CIDRs: routes
            ), hostile)
        }
    }

    func testRejectsNoAnswersOrInvalidRoute() {
        XCTAssertNil(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
            [], includedIPv4CIDRs: routes
        ))
        XCTAssertNil(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
            ["203.0.113.42"], includedIPv4CIDRs: ["broken"]
        ))
        XCTAssertEqual(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
            ["::ffff:10.8.1.1"], includedIPv4CIDRs: routes
        ), "::ffff:10.8.1.1")
    }
    func testRejectsOversizedAndNULNumericAnswers() {
        let publicIP = "203.0.113.42"
        XCTAssertEqual(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
            Array(repeating: publicIP, count: 32), includedIPv4CIDRs: routes
        ), publicIP)
        XCTAssertNil(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
            Array(repeating: publicIP, count: 33), includedIPv4CIDRs: routes
        ))
        for malformed in [
            "203.0.113.42\0unsafe", "\0203.0.113.42",
            String(repeating: "1", count: 46)
        ] {
            XCTAssertNil(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
                [malformed], includedIPv4CIDRs: routes
            ))
            XCTAssertNil(ResolvedUnderlayCandidatePolicy.selectPinnedAddress(
                [publicIP, malformed], includedIPv4CIDRs: routes
            ))
        }
    }

}
