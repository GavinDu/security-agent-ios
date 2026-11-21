import Foundation

@main
struct VPNEventExportSmoke {
    static func main() {
        let at = Date(timeIntervalSince1970: 1_700_000_000)
        let id = UUID()
        let events = [
            VPNEvent(id: id, at: at, event: "starting"),
            VPNEvent(id: UUID(), at: at, event: "endpoint=private.example"),
            VPNEvent(id: UUID(), at: at, event: "privateKey=leaked"),
            VPNEvent(id: UUID(), at: at, event: "connected"),
            VPNEvent(id: UUID(), at: Date(timeIntervalSince1970: .infinity), event: "stopped"),
            VPNEvent(id: UUID(), at: Date(timeIntervalSince1970: 0), event: "stopped")
        ]
        let text = VPNEventExport.redactedText(from: events)
        precondition(text.contains("2023-11-14T22:13:20Z starting"))
        precondition(text.contains("2023-11-14T22:13:20Z connected"))
        precondition(!text.contains("private.example") &&
                     !text.contains("privateKey") &&
                     !text.contains(id.uuidString) &&
                     !text.contains("stopped"))
        precondition(text.components(separatedBy: "\n").count == 4)
        let many = (0..<150).map { index in
            VPNEvent(id: UUID(), at: at, event: index.isMultiple(of: 2) ? "starting" : "connected")
        }
        let bounded = VPNEventExport.redactedText(from: many)
        precondition(bounded.components(separatedBy: "\n").count == 102)
        precondition(bounded.utf8.count < VPNEventHistory.maxFileBytes)
        precondition(VPNEventExport.redactedText(from: []).components(separatedBy: "\n").count == 2)
        print("Redacted VPN export: allowlist, UTC, bounded and malicious event rejection passed")
    }
}
