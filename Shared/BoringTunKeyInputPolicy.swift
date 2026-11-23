import Foundation

/// Validate key *representation* before allocating the Rust BoringTun Tunn.
/// This is not X25519 point-order or handshake authentication validation.
enum BoringTunKeyInputPolicy {
    static func accepts(
        privateKey: Data, serverPublicKey: String, presharedKey: Data?
    ) -> Bool {
        // A completely zeroed secret must never be passed through the FFI.
        guard privateKey.count == 32,
              privateKey.contains(where: { $0 != 0 }),
              presharedKey == nil || presharedKey?.count == 32,
              // Explicit 32-byte zero PSK is cryptographically neutral:
              // nil means no optional PSK; a present PSK must add entropy.
              presharedKey == nil ||
                  presharedKey?.contains(where: { $0 != 0 }) == true,
              // Canonical WireGuard X25519 public key Base64 is 44 bytes.
              // Bound string input BEFORE any Base64 decode allocation.
              serverPublicKey.utf8.count == 44,
              let key = Data(base64Encoded: serverPublicKey),
              key.count == 32,
              key.base64EncodedString() == serverPublicKey,
              key.contains(where: { $0 != 0 }) else {
            return false
        }
        return true
    }
}
