import Foundation
import XCTest
@testable import AgentApp

final class TunnelUnderlayPolicyTests: XCTestCase {
    func testInstalledIPv4RoutesUseSameCIDRAsUnderlayGuard() {
        let routes = TunnelUnderlayPolicy.splitIPv4Routes(
            includedIPv4CIDRs: RouteMode.split.allowedIPs
        )
        XCTAssertEqual(routes, [
            TunnelIPv4Route(destinationAddress: "10.8.0.0", subnetMask: "255.255.255.0")
        ])
    }

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

    func testIPv4MappedIPv6UsesInstalledSplitRoutes() {
        for host in ["::ffff:10.8.0.1", "[::ffff:10.8.0.1]",
                     "::ffff:a08:1", "::FFFF:0A08:0001"] {
            XCTAssertFalse(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: RouteMode.split.allowedIPs
            ), host)
        }
        for host in ["::ffff:203.0.113.42", "[::ffff:10.8.1.1]",
                     "2001:db8::1", "[2001:db8::1]"] {
            XCTAssertTrue(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: RouteMode.split.allowedIPs
            ), host)
        }
        for host in ["::ffff:10.8.0.256", "::ffff:bad::1",
                     "[::ffff:10.8.0.1", "::ffff:10.8.0.1]"] {
            XCTAssertFalse(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: RouteMode.split.allowedIPs
            ), host)
        }
    }

    func testRejectsAmbiguousNumericIPv4FormsAndInvalidRoutes() {
        for host in ["10.8.0.001", "10.8.0.256", "10.8.0.1.", "167837697",
                     "0x0a080001", "0X0A080001", "0x0a.0x08.0x00.0x01",
                     "10.0x08.0.1", "0xC0000214", "0x00000000",
                     "0x0a080001.", "0x0a..0x08.0x00.0x01"] {
            XCTAssertFalse(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: RouteMode.split.allowedIPs
            ))
        }
        XCTAssertTrue(TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: "0xface.home.example", includedIPv4CIDRs: RouteMode.split.allowedIPs
        ))
        XCTAssertFalse(TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: "203.0.113.42", includedIPv4CIDRs: ["0.0.0.0/0"]
        ))
        XCTAssertFalse(TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: "203.0.113.42", includedIPv4CIDRs: ["not-a-cidr"]
        ))
    }
}
