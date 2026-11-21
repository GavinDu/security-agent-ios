import Foundation

@main
struct TunnelUnderlayPolicySmoke {
    static func main() {
        let split = ["10.8.0.0/24"]
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
                     "", "10.8.0.1."] {
            precondition(!TunnelUnderlayPolicy.permitsLiteralEndpoint(
                host: host, includedIPv4CIDRs: split
            ), "Ambiguous numeric IPv4 notation accepted: \(host)")
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
