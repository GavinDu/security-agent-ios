import Foundation

/// App-group marker for a submitted native preference transaction. Only the
/// main-queue app writer creates/removes it; PacketTunnel reads it. A missing
/// terminal callback is NOT proof of cancellation, even after app relaunch.
/// Contains only an opaque UUID, never peer keys, endpoints or profile data.
struct PreferenceWriteJournal {
    enum State: Equatable { case clear, pending(UUID), unavailable }
    enum JournalError: Error { case blocked, notOwned }
    let directory: URL?
    private var marker: URL? { directory?.appendingPathComponent("vpn-preference-write-v1", isDirectory: false) }

    var state: State {
        guard let directory, let marker,
              let parent = try? FileManager.default.attributesOfItem(atPath: directory.path),
              parent[.type] as? FileAttributeType == .typeDirectory else { return .unavailable }
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: marker.path)
            guard attributes[.type] as? FileAttributeType == .typeRegular,
                  (attributes[.size] as? NSNumber)?.intValue == 36,
                  let bytes = try? Data(contentsOf: marker), bytes.count == 36,
                  let text = String(data: bytes, encoding: .utf8),
                  let token = UUID(uuidString: text), token.uuidString == text else {
                return .unavailable
            }
            return .pending(token)
        } catch let error as NSError {
            if error.domain == NSCocoaErrorDomain &&
                (error.code == NSFileNoSuchFileError || error.code == NSFileReadNoSuchFileError) {
                return .clear
            }
            return .unavailable
        }
    }

    func begin() throws -> UUID {
        guard state == .clear, let marker else { throw JournalError.blocked }
        let token = UUID()
        // Atomic replacement avoids partial marker reads across processes.
        // Single writer is the app's main-queue native transaction owner.
        try Data(token.uuidString.utf8).write(to: marker, options: .atomic)
        guard state == .pending(token) else { throw JournalError.blocked }
        return token
    }

    func finish(_ token: UUID) throws {
        guard state == .pending(token), let marker else { throw JournalError.notOwned }
        try FileManager.default.removeItem(at: marker)
        guard state == .clear else { throw JournalError.blocked }
    }

    /// A restart/empty inventory alone never clears an interrupted marker.
    /// This is explicit manual recovery after owner-attested OS restart and
    /// removal of the app's system VPN entry, not automatic rollback proof.
    static func permitsManualReset(ownerConfirmedRestartAndRemoval: Bool,
                                   freshUniqueEmptyInventory: Bool,
                                   nativeOperationInFlight: Bool) -> Bool {
        ownerConfirmedRestartAndRemoval && freshUniqueEmptyInventory && !nativeOperationInFlight
    }
}
