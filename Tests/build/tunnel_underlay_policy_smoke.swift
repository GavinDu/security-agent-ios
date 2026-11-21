import Foundation

@main
struct TunnelUnderlayPolicySmoke {
    static func main() {
        let split = ["10.8.0.0/24"]
        precondition(TunnelUnderlayPolicy.splitIPv4Routes(
            includedIPv4CIDRs: split
        ) == [TunnelIPv4Route(
            destinationAddress: "10.8.0.0", subnetMask: "255.255.255.0"
        )], "Installed NEIPv4Route must derive from same split CIDR")
        precondition(TunnelUnderlayPolicy.splitIPv4Routes(
            includedIPv4CIDRs: ["10.8.0.24/24", "192.168.50.1/25"]
        ) == [
            TunnelIPv4Route(destinationAddress: "10.8.0.0", subnetMask: "255.255.255.0"),
            TunnelIPv4Route(destinationAddress: "192.168.50.0", subnetMask: "255.255.255.128")
        ], "Normalize route destination using its mask")
        precondition(TunnelUnderlayPolicy.splitIPv4Routes(includedIPv4CIDRs: []) == nil)
        precondition(TunnelUnderlayPolicy.splitIPv4Routes(
            includedIPv4CIDRs: ["bogus"]
        ) == nil)
        for host in ["10.8.0.0", "10.8.0.1", "10.8.0.2", "10.8.0.254", "10.8.0.255"] {
            precondition(!TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: split
            ), "Split route must not capture literal outer UDP endpoint: \(host)")
        }
        for host in ["10.8.1.1", "10.7.0.1", "192.168.0.1",
                     "203.0.113.42", "255.255.255.255", "home.example.org"] {
            precondition(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: split
            ), "Legitimate outside-range literal/hostname rejected: \(host)")
        }
        for host in ["10.8.0.01", "10.8.0.001", "10.8.0.256",
                     "10.8.0.", "10.8.0", "167837697", "10..0.1",
                     "", "10.8.0.1.", "0x0a080001", "0X0A080001",
                     "0x0a.0x08.0x00.0x01", "10.0x08.0.1",
                     "0xC0000214", "0x00000000", "0x0a080001.",
                     "0x0a..0x08.0x00.0x01"] {
            precondition(!TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: split
            ), "Ambiguous numeric IPv4 notation accepted: \(host)")
        }
        // Legitimate DNS names with 0x-prefixed labels are not parsed as
        // IP aliases; DNS-answer validation remains a separate #65 gate.
        precondition(TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: "0xface.home.example", includedIPv4CIDRs: split
        ))
        // IPv4-mapped IPv6 aliases must use the same installed split-route
        // CIDR decision even when NWEndpoint receives bracketed URL host.
        for host in ["::ffff:10.8.0.1", "[::ffff:10.8.0.1]",
                     "::ffff:a08:1", "::FFFF:0A08:0001",
                     "::ffff:10.8.0.255"] {
            precondition(!TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: split
            ), "Mapped IPv6 captured inner route: \(host)")
        }
        for host in ["::ffff:203.0.113.42", "[::ffff:10.8.1.1]",
                     "2001:db8::1", "[2001:db8::1]", "::1"] {
            precondition(TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: split
            ), "Safe IPv6 literal rejected: \(host)")
        }
        for host in ["::ffff:10.8.0.256", "::ffff:bad::1",
                     "[::ffff:10.8.0.1", "::ffff:10.8.0.1]"] {
            precondition(!TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: split
            ), "Malformed IPv6 literal accepted: \(host)")
        }
        precondition(TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: "10.8.0.1", includedIPv4CIDRs: ["10.8.1.0/24"]
        ))
        precondition(!TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: "10.8.0.1", includedIPv4CIDRs: ["10.8.0.0/16"]
        ))
        precondition(!TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: "203.0.113.42", includedIPv4CIDRs: ["0.0.0.0/0"]
        ))
        precondition(!TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: "203.0.113.42", includedIPv4CIDRs: []
        ))
        precondition(!TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: "203.0.113.42", includedIPv4CIDRs: ["not-a-cidr"]
        ))
        print("WireGuard literal UDP underlay route containment: passed")
    }
}
