import Foundation

@main struct PreferenceWriteJournalSmoke {
    static func main() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        let journal = PreferenceWriteJournal(directory: dir)
        precondition(journal.state == .clear)
        let token = try journal.begin()
        let restarted = PreferenceWriteJournal(directory: dir)
        precondition(restarted.state == .pending(token))
        do { _ = try restarted.begin(); preconditionFailure("overlap") } catch {}
        do { try restarted.finish(UUID()); preconditionFailure("wrong token") } catch {}
        precondition(restarted.state == .pending(token))
        try restarted.finish(token)
        precondition(journal.state == .clear)
        try Data("damaged".utf8).write(to: dir.appendingPathComponent("vpn-preference-write-v1"))
        precondition(journal.state == .unavailable)
        precondition(PreferenceWriteJournal(directory: nil).state == .unavailable)
        precondition(PreferenceWriteJournal(directory: dir.appendingPathComponent("absent")).state == .unavailable)
        for mask in 0..<8 {
            precondition(PreferenceWriteJournal.permitsManualReset(
                ownerConfirmedRestartAndRemoval: mask & 1 != 0,
                freshUniqueEmptyInventory: mask & 2 != 0,
                nativeOperationInFlight: mask & 4 != 0) == (mask == 3))
        }
        print("Preference journal persistence, ownership, corruption and recovery policy passed")
    }
}
