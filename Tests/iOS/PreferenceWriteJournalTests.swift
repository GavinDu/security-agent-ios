import Foundation
import XCTest
@testable import AgentApp

final class PreferenceWriteJournalTests: XCTestCase {
    func testInterruptedMarkerSurvivesNewJournalInstanceAndRejectsWrongOwner() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        let first = PreferenceWriteJournal(directory: dir)
        XCTAssertEqual(first.state, .clear)
        let token = try first.begin()
        let restarted = PreferenceWriteJournal(directory: dir)
        XCTAssertEqual(restarted.state, .pending(token))
        XCTAssertThrowsError(try restarted.begin())
        XCTAssertThrowsError(try restarted.finish(UUID()))
        XCTAssertEqual(restarted.state, .pending(token))
        try restarted.finish(token)
        XCTAssertEqual(first.state, .clear)
        try Data("corrupt".utf8).write(to: dir.appendingPathComponent("vpn-preference-write-v1"))
        XCTAssertEqual(first.state, .unavailable)
        XCTAssertEqual(PreferenceWriteJournal(directory: nil).state, .unavailable)
    }

    func testManualRecoveryRequiresAttestationFreshEmptyInventoryAndNoWrite() {
        for mask in 0..<8 {
            XCTAssertEqual(PreferenceWriteJournal.permitsManualReset(
                ownerConfirmedRestartAndRemoval: mask & 1 != 0,
                freshUniqueEmptyInventory: mask & 2 != 0,
                nativeOperationInFlight: mask & 4 != 0), mask == 3)
        }
    }
}
