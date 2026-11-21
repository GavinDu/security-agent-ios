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
