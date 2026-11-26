import CryptoKit
import Foundation

enum AgentConstants {
    static let appGroup = "group.com.gavindu.securityagent"
    static let tunnelBundleID = "com.gavindu.securityagent.ios.PacketTunnel"
    static let agentURL = URL(string: "http://10.8.0.1:8080/chat")!
    static let clientAddress = "10.8.0.2/32"
    static let clientIPv6Address = "fd86:ea04:1111::2/128"
    static let serverIPv4 = "10.8.0.1"
}

enum RouteMode: String, Codable, CaseIterable, Identifiable {
    case split
    case full
    var id: String { rawValue }
    var title: String { self == .split ? "Split tunnel" : "Full tunnel" }
    var allowedIPs: [String] {
        self == .split ? ["10.8.0.0/24"] : ["0.0.0.0/0", "::/0"]
    }
}

enum AgentConfigurationError: LocalizedError {
    case invalidPublicKey
    case invalidEndpoint
    case unsafeUnderlayEndpoint
    case invalidSplitRoute
    case incorrectQRType
    case unsupportedQRVersion
    case missingProfile
    case missingAppGroup
    case invalidProfileData
    case nativeProfileMismatch
    case unverifiedFullTunnel
    case preferenceRecoveryRequired

    var errorDescription: String? {
        switch self {
        case .invalidPublicKey: return "WireGuard public key must be a canonical, nonzero 32-byte Base64 value."
        case .invalidEndpoint: return "Enter an endpoint such as home.example.net:51820."
        case .unsafeUnderlayEndpoint: return "Use a usable unicast Mac UDP IP outside the VPN split routes, or a hostname whose resolved A/AAAA addresses are all safe. Loopback, link-local, multicast, and broadcast endpoints are blocked."
        case .invalidSplitRoute: return "The VPN split route does not match the approved private-agent network. Update Security Agent before reconnecting."
        case .incorrectQRType: return "This is not a Mac Mini pairing QR code."
        case .unsupportedQRVersion: return "Unsupported pairing QR format."
        case .missingProfile: return "Pair with your Mac Mini first."
        case .missingAppGroup: return "App Group is unavailable; check signing capabilities."
        case .invalidProfileData: return "WireGuard public profile is invalid or too large. Re-pair with your Mac."
        case .nativeProfileMismatch: return "VPN preferences and paired profile do not match. Disconnect and re-save your Mac pairing in Security Agent before connecting."
        case .preferenceRecoveryRequired: return "VPN preference recovery is required. Do not reconnect until the pending update is resolved."
        case .unverifiedFullTunnel: return "Full tunnel is disabled until encrypted UDP underlay routing and leak safety pass physical iPhone tests. Use split tunnel."
        }
    }
}

struct ServerProfile: Codable, Equatable {
    let publicKey: String
    let endpoint: String
    var routeMode: RouteMode = .split
    var onDemand = false

    func validated() throws -> ServerProfile {
        guard CanonicalWireGuardPublicKeyPolicy.accepts(publicKey) else {
            throw AgentConfigurationError.invalidPublicKey
        }
        // PacketTunnel resolves and pins safe numeric A/AAAA before installing split routes.
        guard !endpoint.isEmpty, !endpoint.contains(where: { $0.isWhitespace || $0.isNewline }),
              let components = URLComponents(string: "udp://\(endpoint)"),
              let host = components.host, !host.isEmpty,
              let port = components.port, (1...65535).contains(port),
              components.user == nil, components.password == nil,
              components.path.isEmpty, components.query == nil, components.fragment == nil else {
            throw AgentConfigurationError.invalidEndpoint
        }
        // The encrypted outer UDP channel cannot be addressed *inside* the
        // same 10.8.0.0/24 split route that would depend on its handshake.
        // Hostname A/AAAA routing still requires physical underlay proof (#65).
        if routeMode == .split && !TunnelUnderlayPolicy.permitsLiteralEndpoint(
            host: host, includedIPv4CIDRs: RouteMode.split.allowedIPs
        ) {
            throw AgentConfigurationError.unsafeUnderlayEndpoint
        }
        return self
    }

    /// Pin the V2 digest schema to these four public fields; future fields
    /// added to ServerProfile must not silently change the native binding.
    private struct BoundPublicProfileV2: Encodable {
        let publicKey: String
        let endpoint: String
        let routeMode: String
        let onDemand: Bool
    }

    /// Binds the public profile stored by the app to the system VPN profile.
    /// Every target hashes the same validated JSON with sorted keys. The
    /// private WireGuard identity and optional PSK are never in this model.
    func publicProfileDigest() throws -> String {
        let canonical = try validated()
        let bound = BoundPublicProfileV2(
            publicKey: canonical.publicKey,
            endpoint: canonical.endpoint,
            routeMode: canonical.routeMode.rawValue,
            onDemand: canonical.onDemand
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(bound)
        return Data(SHA256.hash(data: bytes)).base64EncodedString()
    }

    // Full SHA-256 digest of the canonical WireGuard public key bytes.
    // This is a *comparison aid*, not proof of authenticity by itself:
    // the user must compare it through a trusted out-of-band channel.
    func publicKeyFingerprint() throws -> String {
        _ = try validated()
        guard let bytes = Data(base64Encoded: publicKey), bytes.count == 32 else {
            throw AgentConfigurationError.invalidPublicKey
        }
        let digest = Array(SHA256.hash(data: bytes))
        return stride(from: 0, to: digest.count, by: 4).map { index in
            digest[index..<(index + 4)]
                .map { String(format: "%02X", $0) }
                .joined()
        }.joined(separator: "-")
    }
}

struct PairingQRCode: Codable {
    enum Kind: String, Codable { case iphone, mac }
    let version: Int
    let kind: Kind
    let publicKey: String
    let endpoint: String?

    init(kind: Kind, publicKey: String, endpoint: String? = nil) {
        version = 1
        self.kind = kind
        self.publicKey = publicKey
        self.endpoint = endpoint
    }

    func encodedText() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return String(decoding: try encoder.encode(self), as: UTF8.self)
    }

    static func decodeMac(_ text: String) throws -> ServerProfile {
        // Reject untrusted QR input before allocating/decoding large JSON.
        // Only validated public QR fields enter the existing strict profile
        // parser, which checks UDP endpoint and split-route capture.
        let fields: MacPairingQRInputPolicy.ValidatedFields
        do {
            fields = try MacPairingQRInputPolicy.decode(text)
        } catch MacPairingQRInputPolicy.ValidationError.unsupportedVersion {
            throw AgentConfigurationError.unsupportedQRVersion
        } catch MacPairingQRInputPolicy.ValidationError.invalidPublicKey {
            throw AgentConfigurationError.invalidPublicKey
        } catch {
            throw AgentConfigurationError.incorrectQRType
        }
        return try ServerProfile(publicKey: fields.publicKey, endpoint: fields.endpoint).validated()
    }
}

enum SharedProfileStore {
    private static let key = "serverProfileV1"

    static func load() -> ServerProfile? {
        guard let defaults = UserDefaults(suiteName: AgentConstants.appGroup),
              let bytes = defaults.data(forKey: key),
              SharedProfileDataPolicy.accepts(bytes) else { return nil }
        // A damaged/oversized App Group value never reaches JSONDecoder.
        return try? JSONDecoder().decode(ServerProfile.self, from: bytes).validated()
    }

    static func save(_ profile: ServerProfile) throws {
        let validated = try profile.validated()
        guard let defaults = UserDefaults(suiteName: AgentConstants.appGroup) else {
            throw AgentConfigurationError.missingAppGroup
        }
        let bytes = try JSONEncoder().encode(validated)
        guard SharedProfileDataPolicy.accepts(bytes) else {
            throw AgentConfigurationError.invalidProfileData
        }
        defaults.set(bytes, forKey: key)
        // UserDefaults.set has no error result. Reject a missing/mismatched
        // immediate public-data readback before the native save sequencer
        // reports success or offers to connect. This does not assert durable
        // disk commit or atomicity with NEVPNManager preferences.
        guard SharedProfileReadbackPolicy.accepts(
            expected: bytes, observed: defaults.data(forKey: key)
        ) else {
            throw AgentConfigurationError.invalidProfileData
        }
    }
}

/// Shared location, accessed by app and PacketTunnel on iOS. Missing or
/// unreadable App Group is blocked rather than treated as a clear journal.
enum SharedPreferenceWriteJournal {
    static var current: PreferenceWriteJournal {
        PreferenceWriteJournal(directory: FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: AgentConstants.appGroup))
    }
}
