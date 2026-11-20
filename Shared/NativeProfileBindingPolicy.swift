import Foundation

/// Pure validation gate shared by the app and NetworkExtension. Native
/// preferences and App Group metadata are separate stores, so never infer
/// an atomic commit across them. The SHA-256 digest covers public profile
/// data only; secret WireGuard keys remain exclusively in shared Keychain.
enum NativeProfileBindingPolicy {
    static let requiredVersion = 2
    private static let digestField = "publicProfileDigest"
    private static let versionField = "profileVersion"

    static func metadata(for digest: String) -> [String: Any] {
        [versionField: requiredVersion, digestField: digest]
    }

    static func allowsStart(metadata: [String: Any]?, profileDigest: String?) -> Bool {
        guard let metadata,
              let version = metadata[versionField] as? Int,
              version == requiredVersion,
              let stored = metadata[digestField] as? String,
              let expected = profileDigest,
              let decoded = Data(base64Encoded: expected),
              decoded.count == 32,
              decoded.base64EncodedString() == expected else {
            return false
        }
        return stored == expected
    }
}
