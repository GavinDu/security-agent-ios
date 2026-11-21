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
        guard !addresses.isEmpty else { return nil }
        var selected: String?
        for host in addresses {
            guard !host.isEmpty,
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
                guard usableIPv4Unicast(octets) else { return nil }
            } else if isIPv6 {
                let octets = withUnsafeBytes(of: &ipv6) { Array($0) }
                let mapped = octets.prefix(10).allSatisfy { $0 == 0 } &&
                    octets[10] == 0xff && octets[11] == 0xff
                let isZero = octets.allSatisfy { $0 == 0 }
                let isLoopback = octets.prefix(15).allSatisfy { $0 == 0 } &&
                    octets[15] == 1
                let isLinkLocal = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
                guard !isZero, !isLoopback, !isLinkLocal, octets[0] != 0xff,
                      !mapped || usableIPv4Unicast(Array(octets.suffix(4))) else {
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

    private static func usableIPv4Unicast(_ octets: [UInt8]) -> Bool {
        guard octets.count == 4 else { return false }
        // 0/8, loopback, link-local and multicast/reserved IPv4 cannot be
        // reliably used as a WireGuard remote underlay endpoint.
        return octets[0] != 0 && octets[0] != 127 &&
            !(octets[0] == 169 && octets[1] == 254) && octets[0] < 224
    }
}
