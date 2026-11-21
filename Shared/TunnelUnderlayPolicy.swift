import Foundation

/// Prevent a literal outer WireGuard UDP endpoint from being captured by
/// the same IPv4 split routes that NetworkExtension installs for inner data.
///
/// This policy cannot prove DNS resolution or NWConnection underlay behavior:
/// hostname answers and physical iPhone path selection still require #65.
enum TunnelUnderlayPolicy {
    static func permitsLiteralEndpoint(
        host: String,
        includedIPv4CIDRs: [String]
    ) -> Bool {
        guard !host.isEmpty, !includedIPv4CIDRs.isEmpty else { return false }

        // Hostnames are resolved later by Network.framework. Do not pretend
        // this string-only policy verifies a hostname's final A/AAAA answer.
        let looksNumeric = host.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || $0 == 46
        }
        guard looksNumeric else { return true }

        // inet_aton-style single-number/short/leading-zero IPv4 aliases can
        // be resolved differently by platforms. Reject instead of guessing.
        guard let endpoint = canonicalIPv4(host) else { return false }
        for route in includedIPv4CIDRs {
            let parts = route.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 2,
                  let network = canonicalIPv4(String(parts[0])),
                  let prefix = UInt32(parts[1]), prefix <= 32 else {
                return false
            }
            let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << (32 - prefix)
            if endpoint & mask == network & mask { return false }
        }
        return true
    }

    private static func canonicalIPv4(_ text: String) -> UInt32? {
        let octets = text.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return nil }
        var result: UInt32 = 0
        for part in octets {
            guard !part.isEmpty, part.utf8.count <= 3,
                  (part.count == 1 || part.first != "0"),
                  part.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
                  let value = UInt32(part), value <= 255 else {
                return nil
            }
            result = (result << 8) | value
        }
        return result
    }
}
