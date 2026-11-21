import Foundation

/// Narrow public-key representation gate for stored Mac WireGuard profiles.
/// Does not implement point-order validation or prove peer authenticity.
enum CanonicalWireGuardPublicKeyPolicy {
    static func accepts(_ value: String) -> Bool {
        // A WireGuard public key is exactly 32 bytes encoded as 44 ASCII
        // Base64 characters. Check input length before any decode allocation.
        guard value.utf8.count == 44,
              let bytes = Data(base64Encoded: value),
              bytes.count == 32,
              bytes.base64EncodedString() == value,
              bytes.contains(where: { $0 != 0 }) else {
            return false
        }
        return true
    }
}
