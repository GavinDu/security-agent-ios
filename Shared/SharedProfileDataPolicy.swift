import Foundation

/// Bound the *decoder input* for the public App Group VPN profile.
/// UserDefaults may already have materialized the Data when read; this
/// limit does not claim to cap the OS preference read's memory usage.
/// No WireGuard private key or PSK is stored in this public profile.
enum SharedProfileDataPolicy {
    static let maxEncodedBytes = 4_096

    static func acceptsEncodedByteCount(_ count: Int) -> Bool {
        count > 0 && count <= maxEncodedBytes
    }

    static func accepts(_ bytes: Data) -> Bool {
        acceptsEncodedByteCount(bytes.count)
    }
}
