import Foundation

/// Extension writes only a finite event code and timestamp; UI reads them.
/// No URL, address, key, packet body, arbitrary exception or Rust log text.
enum SharedDiagnostics {
    private static let writerLock = NSLock()

    private static var fileURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AgentConstants.appGroup)?
            .appendingPathComponent("vpn-events.json")
    }

    /// Never load an attacker-modified or damaged App Group file without a
    /// size bound. An atomic writer may replace the path while it is open.
    private static func readBoundedData() -> Data? {
        guard let url = fileURL,
              let file = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? file.close() }
        guard let bytes = try? file.read(upToCount: VPNEventHistory.maxFileBytes + 1),
              bytes.count <= VPNEventHistory.maxFileBytes else { return nil }
        return bytes
    }

    static func events() -> [VPNEvent] {
        guard let bytes = readBoundedData() else { return [] }
        return VPNEventHistory.decode(bytes)
    }

    static func record(_ event: String) {
        guard VPNEventHistory.allows(event), let url = fileURL else { return }
        // Only one writer is expected (PacketTunnel), but callbacks may
        // arrive on different queues. Prevent local lost-update races.
        writerLock.lock()
        defer { writerLock.unlock() }
        guard let data = VPNEventHistory.appending(event, to: readBoundedData()) else { return }
        try? data.write(to: url, options: .atomic)
    }
}
