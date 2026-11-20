import Foundation

// Stores bounded, redacted state transitions only. No private/public keys,
// peer endpoints, IP addresses, payloads, or raw adapter logs.
struct VPNEvent: Codable, Identifiable {
    let id: UUID
    let at: Date
    let event: String
}

enum SharedDiagnostics {
    private static var fileURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AgentConstants.appGroup)?
            .appendingPathComponent("vpn-events.json")
    }

    static func events() -> [VPNEvent] {
        guard let url = fileURL, let data = try? Data(contentsOf: url) else { return [] }
        return (try? JSONDecoder().decode([VPNEvent].self, from: data)) ?? []
    }

    static func record(_ event: String) {
        let allowed: Set<String> = ["starting", "connected", "start_failed", "stopped", "stop_failed"]
        guard allowed.contains(event), let url = fileURL else { return }
        var history = events()
        history.append(VPNEvent(id: UUID(), at: Date(), event: event))
        let bounded = Array(history.suffix(100))
        guard let data = try? JSONEncoder().encode(bounded) else { return }
        try? data.write(to: url, options: .atomic)
    }
}
