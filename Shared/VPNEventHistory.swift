import Foundation

/// Stable, privacy-safe event record shared with the iOS UI.
/// Never add peer endpoints, credentials, packet bodies or arbitrary messages.
struct VPNEvent: Codable, Identifiable, Equatable {
    let id: UUID
    let at: Date
    let event: String
}

/// Pure codec, testable without App Group, Keychain, or NetworkExtension.
enum VPNEventHistory {
    static let maxRecords = 100
    static let maxFileBytes = 32_768
    private static let allowedCodes: Set<String> = [
        "starting", "connected", "start_failed", "stopped", "stop_failed",
        "dns_preflight_busy", "dns_preflight_timeout", "dns_preflight_empty",
        "dns_preflight_failed", "unsafe_underlay_rejected"
    ]

    static func allows(_ code: String) -> Bool {
        allowedCodes.contains(code)
    }

    static func decode(_ bytes: Data) -> [VPNEvent] {
        guard bytes.count <= maxFileBytes,
              let decoded = try? JSONDecoder().decode([VPNEvent].self, from: bytes) else {
            return []
        }
        // Even a modified shared file must never become a free-form text log.
        return Array(decoded.filter { allows($0.event) }.suffix(maxRecords))
    }

    static func appending(
        _ code: String,
        to previous: Data?,
        at timestamp: Date = Date(),
        id: UUID = UUID()
    ) -> Data? {
        guard allows(code) else { return nil }
        var history = previous.map(decode) ?? []
        history.append(VPNEvent(id: id, at: timestamp, event: code))
        let bounded = Array(history.suffix(maxRecords))
        guard let encoded = try? JSONEncoder().encode(bounded),
              encoded.count <= maxFileBytes else { return nil }
        return encoded
    }
}
