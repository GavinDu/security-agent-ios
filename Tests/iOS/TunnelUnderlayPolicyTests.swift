import Foundation
import XCTest
@testable import AgentApp

final class TunnelUnderlayPolicyTests: XCTestCase {
    func testRejectsAllSplitRouteLiteralEndpointBoundaries() {
        for host in ["10.8.0.0", "10.8.0.1", "10.8.0.2", "10.8.0.255"] {
            XCTAssertFalse(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: RouteMode.split.allowedIPs
            ))
        }
    }

    func testAllowsOutsideSplitRouteAndClearlyScopedHostnameFallback() {
        for host in ["10.8.1.1", "192.168.1.20", "203.0.113.42", "home.example.org"] {
            XCTAssertTrue(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: RouteMode.split.allowedIPs
            ))
        }
    }

    func testRejectsAmbiguousNumericIPv4FormsAndInvalidRoutes() {
        for host in ["10.8.0.001", "10.8.0.256", "10.8.0.1.", "167837697"] {
            XCTAssertFalse(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: RouteMode.split.allowedIPs
            ))
        }
        XCTAssertFalse(TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: "203.0.113.42", includedIPv4CIDRs: ["0.0.0.0/0"]
        ))
        XCTAssertFalse(TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: "203.0.113.42", includedIPv4CIDRs: ["not-a-cidr"]
        ))
    }
}
