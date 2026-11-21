import Foundation

/// User-initiated, strictly redacted export. Never serialize raw App Group
/// bytes, UUIDs, endpoints, key material, or arbitrary diagnostics strings.
enum VPNEventExport {
    private static let earliest = Date(timeIntervalSince1970: 946_684_800) // 2000-01-01 UTC
    private static let latest = Date(timeIntervalSince1970: 4_102_444_800) // 2100-01-01 UTC

    static func redactedText(from events: [VPNEvent]) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)

        // Check again even though SharedDiagnostics.events() already filters
        // the persisted file; this is a separate export trust boundary.
        let approved = events.filter {
            VPNEventHistory.allows($0.event) &&
                $0.at.timeIntervalSince1970.isFinite &&
                $0.at >= earliest && $0.at < latest
        }.suffix(VPNEventHistory.maxRecords)

        let lines = approved.map {
            formatter.string(from: $0.at) + " " + $0.event
        }
        return ([
            "Security Agent VPN diagnostics",
            "Redacted event codes and UTC timestamps only"
        ] + lines).joined(separator: "\n")
    }
}
