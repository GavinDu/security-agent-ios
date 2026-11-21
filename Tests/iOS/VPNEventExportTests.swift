import Foundation
import XCTest
@testable import AgentApp

final class VPNEventExportTests: XCTestCase {
    func testOnlyAllowedCodesAndUTCDateReachUserShareText() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let identifier = UUID()
        let records = [
            VPNEvent(id: identifier, at: now, event: "starting"),
            VPNEvent(id: UUID(), at: now, event: "peer=10.8.0.1"),
            VPNEvent(id: UUID(), at: now, event: "connected"),
            VPNEvent(id: UUID(), at: Date(timeIntervalSince1970: 0), event: "stopped")
        ]
        let text = VPNEventExport.redactedText(from: records)
        XCTAssertTrue(text.contains("2023-11-14T22:13:20Z starting"))
        XCTAssertTrue(text.contains("2023-11-14T22:13:20Z connected"))
        XCTAssertFalse(text.contains("peer="))
        XCTAssertFalse(text.contains("10.8.0.1"))
        XCTAssertFalse(text.contains(identifier.uuidString))
        XCTAssertFalse(text.contains("stopped"))
    }

    func testExportIsBoundedEvenWithTamperedHistory() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let records = (0..<200).map { _ in VPNEvent(id: UUID(), at: now, event: "connected") }
        let text = VPNEventExport.redactedText(from: records)
        XCTAssertEqual(text.components(separatedBy: "\n").count, 102)
        XCTAssertLessThan(text.utf8.count, VPNEventHistory.maxFileBytes)
        XCTAssertEqual(VPNEventExport.redactedText(from: []).components(separatedBy: "\n").count, 2)
    }
}
