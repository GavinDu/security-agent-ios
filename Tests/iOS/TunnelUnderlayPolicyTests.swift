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

    func testPrivateSplitContractRejectsAnyRouteExpansionOrDrift() {
        let expected = [TunnelIPv4Route(
            destinationAddress: "10.8.0.0", subnetMask: "255.255.255.0"
        )]
        XCTAssertEqual(TunnelUnderlayPolicy.privateAgentSplitRoutes(
            includedIPv4CIDRs: RouteMode.split.allowedIPs
        ), expected)
        XCTAssertEqual(TunnelUnderlayPolicy.privateAgentSplitRoutes(
            includedIPv4CIDRs: ["10.8.0.7/24"]
        ), expected)
        let unapprovedRoutes: [[String]] = [
            [], ["0.0.0.0/0"], ["10.8.0.0/16"], ["10.8.0.0/25"],
            ["10.8.1.0/24"], ["10.8.0.0/24", "0.0.0.0/0"],
            ["10.8.0.0/24", "192.168.1.0/24"], ["10.8.0.0/24", "::/0"],
            ["10.8.0.0/24", "10.8.0.0/24"], ["invalid"]
        ]
        for unapproved in unapprovedRoutes {
            XCTAssertNil(TunnelUnderlayPolicy.privateAgentSplitRoutes(
                includedIPv4CIDRs: unapproved
            ))
        }
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

    func testRejectsHostControlBytesPercentAndOverlengthBeforeFallback() {
        let routes = RouteMode.split.allowedIPs
        let maxHost = [
            String(repeating: "a", count: 63),
            String(repeating: "b", count: 63),
            String(repeating: "c", count: 63),
            String(repeating: "d", count: 61)
        ].joined(separator: ".")
        XCTAssertEqual(maxHost.utf8.count, 253)
        XCTAssertTrue(TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: maxHost, includedIPv4CIDRs: routes
        ))
        for hostile in [
            "10.8.0.1\0suffix", "10.8.0.1\0", "\010.8.0.1",
            "home\0.example", "host.example.org\n", "host\t.example",
            "host.example.org\u{007F}", "host.example.org\u{0085}",
            "10.8.0.1%lo0", "host%00.example.org", maxHost + "x"
        ] {
            XCTAssertFalse(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: hostile, includedIPv4CIDRs: routes
            ), "Host control/length bypass")
        }
    }

    func testRejectsUnusableLiteralIPv4IPv6AtEarlyProfileBoundary() {
        let routes = RouteMode.split.allowedIPs
        for hostile in [
            "0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1",
            "255.255.255.255", "::", "::1", "fe80::1", "ff02::1",
            "::10.8.0.1", "::ffff:127.0.0.1",
            "::ffff:169.254.1.1", "::ffff:255.255.255.255"
        ] {
            XCTAssertFalse(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: hostile, includedIPv4CIDRs: routes
            ), "Invalid encrypted UDP underlay: \(hostile)")
        }
        for valid in [
            "192.168.1.10", "203.0.113.42", "2001:db8::1",
            "[2001:db8::1]", "fd00::42", "[fd00::42]",
            "::ffff:192.168.1.10", "home.example.org"
        ] {
            XCTAssertTrue(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: valid, includedIPv4CIDRs: routes
            ), "Valid underlay blocked: \(valid)")
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
