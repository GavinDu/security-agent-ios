import Foundation

@main
struct VPNEventHistorySmoke {
    static func main() throws {
        let timestamp = Date(timeIntervalSince1970: 1_700_000_000)
        var bytes: Data? = nil
        for _ in 0..<121 {
            bytes = VPNEventHistory.appending("connected", to: bytes, at: timestamp)
            precondition(bytes != nil)
        }
        let records = VPNEventHistory.decode(bytes!)
        precondition(records.count == VPNEventHistory.maxRecords)
        precondition(records.allSatisfy { $0.event == "connected" })
        precondition(records.allSatisfy { $0.at == timestamp })
        precondition(bytes!.count < VPNEventHistory.maxFileBytes)

        let rejected = VPNEventHistory.appending("endpoint=private.example", to: bytes)
        precondition(rejected == nil)
        precondition(!VPNEventHistory.allows("something_unknown"))
        precondition(VPNEventHistory.allows("start_failed"))
        for code in ["dns_preflight_busy", "dns_preflight_timeout", "dns_preflight_empty",
                     "dns_preflight_failed", "unsafe_underlay_rejected"] {
            let encoded = VPNEventHistory.appending(code, to: nil, at: timestamp)
            precondition(encoded != nil)
            precondition(VPNEventHistory.decode(encoded!).map(\.event) == [code])
        }
        precondition(!VPNEventHistory.allows("dns_preflight_failed: private.example"))

        let polluted = [
            VPNEvent(id: UUID(), at: timestamp, event: "connected"),
            VPNEvent(id: UUID(), at: timestamp, event: "key-should-never-export"),
            VPNEvent(id: UUID(), at: timestamp, event: "stopped")
        ]
        let sanitized = VPNEventHistory.decode(try JSONEncoder().encode(polluted))
        precondition(sanitized.map(\.event) == ["connected", "stopped"])
        precondition(VPNEventHistory.decode(Data("not-json".utf8)).isEmpty)
        precondition(VPNEventHistory.decode(Data(repeating: 0x41, count: VPNEventHistory.maxFileBytes + 1)).isEmpty)
        precondition(VPNEventHistory.decode(Data()).isEmpty)

        // Tampered persisted timestamps must not reach either display or export.
        let earliest = Date(timeIntervalSince1970: 946_684_800)
        let latest = Date(timeIntervalSince1970: 4_102_444_800)
        let dated = [
            VPNEvent(id: UUID(), at: earliest.addingTimeInterval(-1), event: "stopped"),
            VPNEvent(id: UUID(), at: earliest, event: "starting"),
            VPNEvent(id: UUID(), at: latest.addingTimeInterval(-1), event: "connected"),
            VPNEvent(id: UUID(), at: latest, event: "stopped")
        ]
        precondition(VPNEventHistory.decode(try JSONEncoder().encode(dated)).map(\.event) == ["starting", "connected"])
        for invalid in [Date(timeIntervalSince1970: .infinity), Date(timeIntervalSince1970: .nan), latest] {
            precondition(VPNEventHistory.appending("starting", to: bytes, at: invalid) == nil)
        }

        let repaired = VPNEventHistory.appending("starting", to: Data("invalid".utf8), at: timestamp)
        precondition(repaired != nil)
        precondition(VPNEventHistory.decode(repaired!).map(\.event) == ["starting"])
        print("VPN event code allowlist, bounded retention, invalid-data recovery and privacy sanitization passed")
    }
}
