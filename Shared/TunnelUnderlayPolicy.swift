import Foundation

/// Exact IPv4 route values used by NEPacketTunnelNetworkSettings. The outer
/// WireGuard UDP guard consumes this same parsed route model, so the guard
/// and installed routes cannot silently drift apart.
struct TunnelIPv4Route: Equatable {
    let destinationAddress: String
    let subnetMask: String
}

enum TunnelUnderlayPolicy {
    /// Build installed routes from the single source of truth:
    /// RouteMode.split.allowedIPs. Fail closed on malformed/empty CIDRs.
    static func splitIPv4Routes(
        includedIPv4CIDRs: [String]
    ) -> [TunnelIPv4Route]? {
        guard !includedIPv4CIDRs.isEmpty else { return nil }
        var routes: [TunnelIPv4Route] = []
        for cidr in includedIPv4CIDRs {
            guard let parsed = parseCIDR(cidr) else { return nil }
            routes.append(TunnelIPv4Route(
                destinationAddress: dottedIPv4(parsed.network & parsed.mask),
                subnetMask: dottedIPv4(parsed.mask)
            ))
        }
        return routes
    }

    /// Prevent a *literal* encrypted outer UDP destination from being
    /// captured by the installed inner IPv4 route. DNS answers, NAT64 and
    /// physical underlay binding still require #65 real-device verification.
    static func permitsLiteralEndpoint(
        host: String,
        includedIPv4CIDRs: [String]
    ) -> Bool {
        guard !host.isEmpty, !includedIPv4CIDRs.isEmpty else { return false }
        // Validate route syntax even for a hostname, so invalid route config
        // never makes endpoint validation appear successful.
        let parsedRoutes = includedIPv4CIDRs.compactMap(parseCIDR)
        guard parsedRoutes.count == includedIPv4CIDRs.count else { return false }

        let looksNumeric = host.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || $0 == 46
        }
        guard looksNumeric else { return true }

        // Single-integer, abbreviated and leading-zero forms can be
        // interpreted differently by platform resolvers; reject them.
        guard let endpoint = canonicalIPv4(host) else { return false }
        for route in parsedRoutes {
            if endpoint & route.mask == route.network & route.mask {
                return false
            }
        }
        return true
    }

    private static func parseCIDR(_ text: String) -> (network: UInt32, mask: UInt32)? {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let network = canonicalIPv4(String(parts[0])),
              let prefix = UInt32(parts[1]), prefix <= 32 else {
            return nil
        }
        let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << (32 - prefix)
        return (network, mask)
    }

    private static func dottedIPv4(_ address: UInt32) -> String {
        [24, 16, 8, 0].map { offset in
            String((address >> offset) & 0xff)
        }.joined(separator: ".")
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
