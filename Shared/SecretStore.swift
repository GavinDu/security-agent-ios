import CryptoKit
import Foundation
import Security

// This file is compiled into both the app and the packet tunnel.
// Do not add these values to providerConfiguration, UserDefaults or App Group files.
enum SharedKeychain {
    private static let service = "com.gavindu.securityagent.wireguard"
    private static let identityAccount = "iphone.privateKey"
    private static let pskAccount = "wireguard.preSharedKey"
    private static let boundPSKAccount = "wireguard.preSharedKey.bound.v1"
    private static let rotationStageAccount = "iphone.rotation.stage.v1"
    private static let pskStageAccount = "wireguard.preSharedKey.stage.v1"

    enum KeychainError: LocalizedError {
        case missingAccessGroup
        case missingSecret
        case invalidSecret
        case unboundPreSharedKey
        case osStatus(OSStatus)

        var errorDescription: String? {
            switch self {
            case .missingAccessGroup: return "Shared Keychain entitlement is missing or unexpanded."
            case .missingSecret: return "WireGuard identity not found; open the app to pair."
            case .invalidSecret: return "Invalid or mismatched WireGuard key stored in Keychain."
            case .unboundPreSharedKey: return "Legacy preshared key is not bound to this peer. Authenticated reprovisioning is required; no automatic no-PSK fallback is permitted."
            case .osStatus(let status): return "Keychain error \(status)."
            }
        }
    }

    private static func accessGroup() -> String {
        // Apple permits iOS App Group identifiers to be used directly as
        // Keychain access groups. Both signed targets hold this entitlement.
        // Avoid relying on unresolved $(AppIdentifierPrefix) runtime strings.
        AgentConstants.appGroup
    }

    private static func query(_ account: String) throws -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup()
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
        guard let data = item as? Data else { throw KeychainError.invalidSecret }
        return data
    }

    static func existingIdentity() throws -> Data {
        guard let secret = try read(identityAccount) else { throw KeychainError.missingSecret }
        // Reject even a correctly sized but zero-filled stored identity.
        // The FFI would reject it later; do not expose it to pairing first.
        guard WireGuardPrivateIdentityPolicy.accepts(secret) else {
            throw KeychainError.invalidSecret
        }
        return secret
    }

    static func createIdentityIfNeeded() throws -> Data {
        if let existing = try read(identityAccount) {
            // Present invalid Keychain material is not an absent identity:
            // fail closed rather than replacing an existing device key.
            guard WireGuardPrivateIdentityPolicy.accepts(existing) else {
                throw KeychainError.invalidSecret
            }
            return existing
        }
        // SecItemAdd is atomic across the app and PacketTunnel processes.
        // Never upsert an identity: a loser of this race must adopt the
        // already persisted key rather than replace its enrolled public key.
        let candidate = Curve25519.KeyAgreement.PrivateKey().rawRepresentation
        return try ImmutableIdentityInstaller.install(
            candidate: candidate,
            insertIfAbsent: { newKey in
                var q = try query(identityAccount)
                q[kSecValueData as String] = newKey
                q[kSecAttrAccessible as String] =
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                let status = SecItemAdd(q as CFDictionary, nil)
                switch status {
                case errSecSuccess:
                    return .inserted
                case errSecDuplicateItem:
                    return .alreadyExists
                default:
                    throw KeychainError.osStatus(status)
                }
            },
            readExisting: { try read(identityAccount) }
        )
    }

    static func publicKeyBase64() throws -> String {
        let secret = try createIdentityIfNeeded()
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret)
        return key.publicKey.rawRepresentation.base64EncodedString()
    }

    private static func optionalPreSharedKey() throws -> Data? {
        guard let data = try read(pskAccount) else { return nil }
        guard data.count == 32 else { throw KeychainError.invalidSecret }
        // A present but all-zero PSK is the neutral/default key, not an
        // authenticated extra secret. Fail closed instead of silently
        // treating it as an enrolled preshared key.
        guard data.contains(where: { $0 != 0 }) else {
            throw KeychainError.invalidSecret
        }
        return data
    }

    /// Future authenticated client transaction owner only. No UI or tunnel
    /// caller. The independently pinned signing identity and expected
    /// receipt context must already have been established out of band.
    /// Atomic Keychain claim prevents app/extension racing the same request;
    /// this is not a native preferences commit or permission to start VPN.
    static func claimVerifiedEnrollmentReceipt(_ verified: VerifiedEnrollmentReceiptPolicy.Verified)
        throws -> VerifiedEnrollmentReceiptPolicy.Claim {
        let account = "wireguard.enrollment.claim.v1." + verified.requestID.uuidString.lowercased()
        return try VerifiedEnrollmentReceiptPolicy.claim(verified, verifyLocalState: {
            let active = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: existingIdentity())
                .publicKey.rawRepresentation.base64EncodedString()
            guard active == verified.clientPublicKey,
                  let profile = SharedProfileStore.load(),
                  profile.publicKey == verified.serverPublicKey, profile.requiredPSK == nil,
                  try read(pskAccount) == nil, try read(boundPSKAccount) == nil,
                  try read(pskStageAccount) == nil, try read(rotationStageAccount) == nil
                  else { throw KeychainError.invalidSecret }
        }, readClaim: {
            // Scope readback to the same non-synchronizable account.
            var q = try query(account)
            q[kSecAttrSynchronizable as String] = false
            q[kSecReturnData as String] = true
            q[kSecMatchLimit as String] = kSecMatchLimitOne
            var item: CFTypeRef?
            let status = SecItemCopyMatching(q as CFDictionary, &item)
            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess else { throw KeychainError.osStatus(status) }
            guard let data = item as? Data else { throw KeychainError.invalidSecret }
            return data
        }, insertIfAbsent: { bytes in
            var q = try query(account)
            q[kSecValueData as String] = bytes
            q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            q[kSecAttrSynchronizable as String] = false
            let status = SecItemAdd(q as CFDictionary, nil)
            switch status {
            case errSecSuccess: return .inserted
            case errSecDuplicateItem: return .alreadyExists
            default: throw KeychainError.osStatus(status)
            }
        })
    }

    /// Only the exact client identity already selected for this codec can
    /// select a bound PSK. The legacy account is validated but never used.
    static func boundPreSharedKey(serverPublicKey: String, clientPrivateKey: Data,
                                  requirement: PeerPSKRequirement?) throws -> Data? {
        guard WireGuardPrivateIdentityPolicy.accepts(clientPrivateKey) else { throw KeychainError.invalidSecret }
        let clientPublicKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: clientPrivateKey)
            .publicKey.rawRepresentation.base64EncodedString()
        let legacyPresent = try optionalPreSharedKey() != nil
        guard !legacyPresent else { throw KeychainError.unboundPreSharedKey }
        let record = try read(boundPSKAccount)
        do {
            return try PeerPSKBindingPolicy.select(serverPublicKey: serverPublicKey,
                clientPublicKey: clientPublicKey, legacyPresent: legacyPresent, boundRecord: record,
                requirement: requirement)
        } catch {
            throw KeychainError.invalidSecret
        }
    }

    /// Future authenticated provisioning owner only; no UI/transport caller.
    /// Initial enrollment only, never an automatic legacy migration or rekey.
    /// The caller must own the cross-store transaction; these local readbacks
    /// do not prove exclusion of another writer or a remote commit.
    static func stageInitialPreSharedKey(serverPublicKey: String,
                                        requirement: PeerPSKRequirement,
                                        secret: Data) throws -> PeerPSKBindingPolicy.StageReceipt {
        try PeerPSKBindingPolicy.stageInitial(serverPublicKey: serverPublicKey,
            requirement: requirement, secret: secret,
            verifyLocalState: {
                let active = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: existingIdentity())
                    .publicKey.rawRepresentation.base64EncodedString()
                guard active == requirement.clientPublicKey,
                      let profile = SharedProfileStore.load(),
                      profile.publicKey == serverPublicKey, profile.requiredPSK == nil,
                      try read(pskAccount) == nil, try read(boundPSKAccount) == nil,
                      try read(rotationStageAccount) == nil else { throw KeychainError.invalidSecret }
            },
            readStage: { try read(pskStageAccount) },
            insertIfAbsent: { bytes in
                var q = try query(pskStageAccount)
                q[kSecValueData as String] = bytes
                q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                q[kSecAttrSynchronizable as String] = false
                let status = SecItemAdd(q as CFDictionary, nil)
                guard status == errSecSuccess || status == errSecDuplicateItem else {
                    throw KeychainError.osStatus(status)
                }
            })
    }

    /// Local readback gate only. Rotation of PSK-protected peers requires
    /// a coordinated authenticated protocol, not this unprotected stage.
    private static func rotationActivePublicKey(binding: IdentityRotationStagePolicy.Binding) throws -> String {
        guard let profile = SharedProfileStore.load(),
              profile.publicKey == binding.serverPublicKey, profile.requiredPSK == nil,
              try read(pskAccount) == nil, try read(boundPSKAccount) == nil,
              try read(pskStageAccount) == nil else { throw KeychainError.invalidSecret }
        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: existingIdentity())
            .publicKey.rawRepresentation.base64EncodedString()
    }

    /// Future rotation owner only; not called by UI or PacketTunnel.
    /// The active identity remains immutable. No candidate can be activated
    /// or discarded until the authenticated rotation protocol is implemented.
    static func stageRotationCandidate(binding: IdentityRotationStagePolicy.Binding)
        throws -> IdentityRotationStagePolicy.Receipt {
        func publicKey(_ secret: Data) throws -> String {
            try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret)
                .publicKey.rawRepresentation.base64EncodedString()
        }
        return try IdentityRotationStagePolicy.stage(
            binding: binding,
            readActivePublicKey: { try rotationActivePublicKey(binding: binding) },
            readStage: { try read(rotationStageAccount) },
            generateCandidate: { Curve25519.KeyAgreement.PrivateKey().rawRepresentation },
            derivePublicKey: publicKey,
            insertIfAbsent: { bytes in
                var q = try query(rotationStageAccount)
                q[kSecValueData as String] = bytes
                q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                q[kSecAttrSynchronizable as String] = false
                let status = SecItemAdd(q as CFDictionary, nil)
                switch status {
                case errSecSuccess: return .inserted
                case errSecDuplicateItem: return .alreadyExists
                default: throw KeychainError.osStatus(status)
                }
            }
        )
    }

    /// Read only, no candidate generation or Keychain mutation. The caller
    /// must still hold the authenticated cross-store transaction lease.
    static func recoverRotationCandidate(binding: IdentityRotationStagePolicy.Binding)
        throws -> IdentityRotationStagePolicy.Receipt {
        try IdentityRotationStagePolicy.recover(binding: binding,
            readActivePublicKey: { try rotationActivePublicKey(binding: binding) },
            readStage: { try read(rotationStageAccount) },
            derivePublicKey: { secret in
                try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret)
                    .publicKey.rawRepresentation.base64EncodedString()
            })
    }

    // PSKs must be provisioned to BOTH ends over an authenticated channel.
    // The QR handshake does not invent an unmatched PSK automatically.
}
