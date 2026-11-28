import Foundation
import Security

/// Mac-only data-protection Keychain adapter; deliberately no fallback to
/// legacy file-based keychain, iOS App Group, preferences or disk.
/// Signed access/entitlement and privileged daemon custody still require
/// verification. No UI or daemon caller until owner authentication exists.
enum MacEnrollmentSignerStore {
    enum StoreError: Error { case invalidServer, invalidItem, osStatus(OSStatus) }
    private static func query(_ server: String) throws -> [String: Any] {
        guard CanonicalWireGuardPublicKeyPolicy.accepts(server) else { throw StoreError.invalidServer }
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.gavindu.securityagent.mac.enrollment-signer.v1",
            kSecAttrAccount as String: server,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false
        ]
    }
    private static func read(_ server: String) throws -> Data? {
        var q = try query(server)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw StoreError.osStatus(status) }
        guard let data = item as? Data else { throw StoreError.invalidItem }
        return data
    }
    /// Explicit first-time commissioning by future trusted owner only.
    static func commission(server: String, readVerifiedServer: () throws -> String)
        throws -> MacEnrollmentSignerPolicy.PublicIdentity {
        try MacEnrollmentSignerPolicy.commission(server: server, readVerifiedServer: readVerifiedServer,
            readRecord: { try read(server) }, insertIfAbsent: { bytes in
                var q = try query(server)
                q[kSecValueData as String] = bytes
                q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                let status = SecItemAdd(q as CFDictionary, nil)
                guard status == errSecSuccess || status == errSecDuplicateItem else {
                    throw StoreError.osStatus(status)
                }
            })
    }
    static func existing(server: String, expectedSigner: Data, readVerifiedServer: () throws -> String)
        throws -> MacEnrollmentSignerPolicy.PublicIdentity {
        try MacEnrollmentSignerPolicy.existing(server: server, expectedSigner: expectedSigner,
            readVerifiedServer: readVerifiedServer, readRecord: { try read(server) })
    }
}
