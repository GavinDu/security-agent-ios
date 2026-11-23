import Foundation

/// A stored Curve25519 WireGuard private identity must be a valid-length,
/// nonzero key before either the app or PacketTunnel uses it. This validates
/// representation, not random entropy, peer authentication, or key ownership.
enum WireGuardPrivateIdentityPolicy {
    static func accepts(_ key: Data) -> Bool {
        key.count == 32 && key.contains(where: { $0 != 0 })
    }
}
