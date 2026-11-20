import CryptoKit
import Foundation
import Security

// This file is compiled into both the app and the packet tunnel.
// Do not add these values to providerConfiguration, UserDefaults or App Group files.
enum SharedKeychain {
    private static let service = "com.gavindu.securityagent.wireguard"
    private static let identityAccount = "iphone.privateKey"
    private static let pskAccount = "wireguard.preSharedKey"

    enum KeychainError: LocalizedError {
        case missingAccessGroup
        case missingSecret
        case invalidSecret
        case osStatus(OSStatus)

        var errorDescription: String? {
            switch self {
            case .missingAccessGroup: return "Shared Keychain entitlement is missing or unexpanded."
            case .missingSecret: return "WireGuard identity not found; open the app to pair."
            case .invalidSecret: return "Invalid WireGuard key stored in Keychain."
            case .osStatus(let status): return "Keychain error \(status)."
            }
        }
    }

    private static func accessGroup() throws -> String {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "AgentKeychainAccessGroup") as? String,
              !group.isEmpty, !group.contains("$(") else {
            throw KeychainError.missingAccessGroup
        }
        return group
    }

    private static func query(_ account: String) throws -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: try accessGroup()
        ]
    }

    static func read(_ account: String) throws -> Data? {
        var q = try query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainError.osStatus(status) }
        return item as? Data
    }

    static func write(_ value: Data, account: String) throws {
        var q = try query(account)
        q[kSecValueData as String] = value
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let result = SecItemUpdate(
                try query(account) as CFDictionary,
                [kSecValueData as String: value] as CFDictionary
            )
            guard result == errSecSuccess else { throw KeychainError.osStatus(result) }
        } else if status != errSecSuccess {
            throw KeychainError.osStatus(status)
        }
    }

    static func existingIdentity() throws -> Data {
        guard let secret = try read(identityAccount) else { throw KeychainError.missingSecret }
        guard secret.count == 32 else { throw KeychainError.invalidSecret }
        return secret
    }

    static func createIdentityIfNeeded() throws -> Data {
        if let existing = try read(identityAccount) {
            guard existing.count == 32 else { throw KeychainError.invalidSecret }
            return existing
        }
        let privateKey = Curve25519.KeyAgreement.PrivateKey().rawRepresentation
        try write(privateKey, account: identityAccount)
        return privateKey
    }

    static func publicKeyBase64() throws -> String {
        let secret = try createIdentityIfNeeded()
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret)
        return key.publicKey.rawRepresentation.base64EncodedString()
    }

    static func optionalPreSharedKey() throws -> Data? {
        guard let data = try read(pskAccount) else { return nil }
        guard data.count == 32 else { throw KeychainError.invalidSecret }
        return data
    }

    // PSKs must be provisioned to BOTH ends over an authenticated channel.
    // The QR handshake does not invent an unmatched PSK automatically.
}
