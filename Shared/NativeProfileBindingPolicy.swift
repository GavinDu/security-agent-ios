import Foundation

/// Pure validation gate shared by the app and NetworkExtension. Native
/// preferences and App Group metadata are separate stores, so never infer
/// an atomic commit across them. The SHA-256 digest covers public profile
/// data only; secret WireGuard keys remain exclusively in shared Keychain.
enum NativeProfileBindingPolicy {
    static let requiredVersion = 2
    static let pskRequiredVersion = 3
    private static let digestField = "publicProfileDigest"
    private static let versionField = "profileVersion"

    static func metadata(for digest: String, version: Int = requiredVersion) -> [String: Any] {
        [versionField: version, digestField: digest]
    }

    static func requiresPSK(metadata: [String: Any]?) -> Bool {
        metadata?[versionField] as? Int == pskRequiredVersion
    }

    static func allowsStart(metadata: [String: Any]?, profileDigest: String?,
                            expectedVersion: Int = requiredVersion) -> Bool {
        guard expectedVersion == requiredVersion || expectedVersion == pskRequiredVersion,
              let metadata,
              let version = metadata[versionField] as? Int,
              version == expectedVersion,
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
