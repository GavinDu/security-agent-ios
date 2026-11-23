import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A *pure* preflight for already resolved A/AAAA addresses. It does not
/// perform DNS, create an NWConnection, or certify a physical underlay route.
/// #95 must pin the selected numeric IP before installing tunnel routes.
enum ResolvedUnderlayCandidatePolicy {
    /// Fail closed if ANY candidate is malformed or captured by the inner
    /// split route. Preserves the resolver's order to make selection stable
    /// for an identical response; never hands a hostname back for re-resolution.
    static func selectPinnedAddress(
        _ addresses: [String], includedIPv4CIDRs: [String]
    ) -> String? {
        // The system DNS lookup returns at most 32 answers. Enforce that
        // contract here too, including for injected/reused resolver results.
        guard !addresses.isEmpty, addresses.count <= 32 else { return nil }
        var selected: String?
        for host in addresses {
            // A numeric IPv6 literal (including dotted IPv4 tail) is at
            // most 45 ASCII bytes. Reject NUL before withCString/inet_pton:
            // otherwise C may validate a truncated prefix, not Swift input.
            guard !host.isEmpty, host.utf8.count <= 45,
                  !host.contains("\0"),
                  host == host.trimmingCharacters(in: .whitespacesAndNewlines),
                  !host.contains("%"), !host.contains("["),
                  !host.contains("]") else {
                return nil
            }
            var ipv4 = in_addr()
            var ipv6 = in6_addr()
            let isIPv4 = host.withCString {
                inet_pton(AF_INET, $0, &ipv4)
            } == 1
            let isIPv6 = host.withCString {
                inet_pton(AF_INET6, $0, &ipv6)
            } == 1
            // A parsed IP can still be unusable as an encrypted UDP peer
            // (unspecified, loopback, multicast or interface-scoped link-local).
            // Reject before handing any candidate to a future resolver consumer.
            if isIPv4 {
                let octets = withUnsafeBytes(of: &ipv4) { Array($0) }
                guard TunnelUnderlayPolicy.usableIPv4Unicast(octets) else { return nil }
            } else if isIPv6 {
                let octets = withUnsafeBytes(of: &ipv6) { Array($0) }
                let mapped = octets.prefix(10).allSatisfy { $0 == 0 } &&
                    octets[10] == 0xff && octets[11] == 0xff
                guard TunnelUnderlayPolicy.usableIPv6Unicast(octets),
                      !mapped || TunnelUnderlayPolicy.usableIPv4Unicast(
                        Array(octets.suffix(4))
                      ) else {
                    return nil
                }
            }
            guard isIPv4 || isIPv6,
                  TunnelUnderlayPolicy.permitsLiteralEndpoint(
                    host: host, includedIPv4CIDRs: includedIPv4CIDRs
                  ) else {
                return nil
            }
            if selected == nil { selected = host }
        }
        return selected
    }

}
