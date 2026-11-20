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
    case incorrectQRType
    case unsupportedQRVersion
    case missingProfile
    case missingAppGroup

    var errorDescription: String? {
        switch self {
        case .invalidPublicKey: return "WireGuard public key must be 32 bytes of base64."
        case .invalidEndpoint: return "Enter an endpoint such as home.example.net:51820."
        case .incorrectQRType: return "This is not a Mac Mini pairing QR code."
        case .unsupportedQRVersion: return "Unsupported pairing QR format."
        case .missingProfile: return "Pair with your Mac Mini first."
        case .missingAppGroup: return "App Group is unavailable; check signing capabilities."
        }
    }
}

struct ServerProfile: Codable, Equatable {
    let publicKey: String
    let endpoint: String
    var routeMode: RouteMode = .split
    var onDemand = false

    func validated() throws -> ServerProfile {
        guard let bytes = Data(base64Encoded: publicKey), bytes.count == 32 else {
            throw AgentConfigurationError.invalidPublicKey
        }
        // NetworkExtension/WireGuardKit validates host resolution at connect time.
        guard !endpoint.isEmpty, !endpoint.contains(where: { $0.isWhitespace || $0.isNewline }),
              let components = URLComponents(string: "udp://\(endpoint)"),
              let host = components.host, !host.isEmpty,
              let port = components.port, (1...65535).contains(port),
              components.user == nil, components.password == nil,
              components.path.isEmpty, components.query == nil, components.fragment == nil else {
            throw AgentConfigurationError.invalidEndpoint
        }
        return self
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
        let payload = try JSONDecoder().decode(PairingQRCode.self, from: Data(text.utf8))
        guard payload.version == 1 else { throw AgentConfigurationError.unsupportedQRVersion }
        guard payload.kind == .mac, let endpoint = payload.endpoint else {
            throw AgentConfigurationError.incorrectQRType
        }
        return try ServerProfile(publicKey: payload.publicKey, endpoint: endpoint).validated()
    }
}

enum SharedProfileStore {
    private static let key = "serverProfileV1"

    static func load() -> ServerProfile? {
        guard let defaults = UserDefaults(suiteName: AgentConstants.appGroup),
              let bytes = defaults.data(forKey: key) else { return nil }
        return try? JSONDecoder().decode(ServerProfile.self, from: bytes).validated()
    }

    static func save(_ profile: ServerProfile) throws {
        let validated = try profile.validated()
        guard let defaults = UserDefaults(suiteName: AgentConstants.appGroup) else {
            throw AgentConfigurationError.missingAppGroup
        }
        defaults.set(try JSONEncoder().encode(validated), forKey: key)
    }
}
