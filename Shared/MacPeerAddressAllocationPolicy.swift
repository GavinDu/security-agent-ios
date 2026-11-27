import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Pure Mac-side reservation proposal. Never modifies WireGuard config,
/// persists keys, or asserts a physical client has been provisioned.
/// The current iOS PacketTunnel still uses a fixed .2 address; callers MUST
/// not activate second-peer reservations before implementing dynamic iOS
/// network settings and authenticated Mac roster transactions (#20).
struct MacPeerAddressReservation: Codable, Equatable, Sendable {
    let publicKey: String
    let slot: UInt8

    /// The single integer is the source of truth, never user-entered CIDRs.
    var ipv4CIDR: String { "10.8.0.\(slot)/32" }
    var ipv6CIDR: String { "fd86:ea04:1111::\(String(slot, radix: 16))/128" }
    var allowedIPs: String { "\(ipv4CIDR), \(ipv6CIDR)" }
}

enum MacPeerAddressAllocationPolicy {
    // .1 is the Mac WireGuard server, .0 the network, .255 broadcast.
    private static let firstClient: UInt8 = 2
    private static let lastClient: UInt8 = 254
    static let maxClients = 253

    /// Deterministic, fail-closed, side-effect-free lowest-slot selection.
    /// An inconsistent or duplicated existing registry NEVER gets repaired
    /// silently. Real enrollment/revocation must be a separate transaction.
    static func nextReservation(
        publicKey: String, existing: [MacPeerAddressReservation]
    ) -> MacPeerAddressReservation? {
        guard IPhonePairingImportPolicy.validatedPublicKey(publicKey) != nil,
              existing.count < maxClients else { return nil }

        var keys = Set<String>()
        var slots = Set<UInt8>()
        for reservation in existing {
            guard IPhonePairingImportPolicy.validatedPublicKey(reservation.publicKey) != nil,
                  reservation.slot >= firstClient,
                  reservation.slot <= lastClient,
                  keys.insert(reservation.publicKey).inserted,
                  slots.insert(reservation.slot).inserted else {
                return nil
            }
        }
        guard !keys.contains(publicKey) else { return nil }
        for number in Int(firstClient)...Int(lastClient) {
            let slot = UInt8(number)
            if !slots.contains(slot) {
                return MacPeerAddressReservation(publicKey: publicKey, slot: slot)
            }
        }
        return nil
    }
}


/// Public-only transaction values. No authorization or privileged daemon
/// calls occur here. The eventual daemon must supply complete authoritative
/// readback and use the persistent coordinator before live use (#20).
struct MacPeerRosterSnapshot: Codable, Equatable, Sendable {
    let epoch: UUID
    let revision: UInt64
    let peers: [MacPeerAddressReservation]
}
enum MacPeerRosterMutation: Sendable {
    case enroll(publicKey: String)
    case revoke(MacPeerAddressReservation)
}
struct MacPeerRosterPlan: Codable, Equatable, Sendable {
    let id: UUID
    let before: MacPeerRosterSnapshot
    let after: [MacPeerAddressReservation]
}
enum MacPeerRosterResolution: Equatable, Sendable {
    case committed, rolledBack, unverified, stale
}

/// Serializes callers. Live daemon use requires the persistent initializer,
/// administrator authorization and terminal operation fencing. The legacy
/// in-memory initializer is reserved for pure policy tests and proposals.
actor MacPeerRosterCoordinator {
    private var current: MacPeerRosterSnapshot
    private var pending: MacPeerRosterPlan?
    private let journal: MacPeerRosterJournal?
    private var persistenceBlocked = false

    init?(peers: [MacPeerAddressReservation], revision: UInt64 = 0) {
        guard let canonical = Self.canonicalRoster(peers) else { return nil }
        current = MacPeerRosterSnapshot(epoch: UUID(), revision: revision, peers: canonical)
        journal = nil
    }

    /// Existing journal only. Missing, corrupt or wrong-server state is
    /// never replaced with an empty roster on restart.
    init?(journal: MacPeerRosterJournal) {
        guard let record = try? journal.load() else { return nil }
        current = record.current
        pending = record.pending
        self.journal = journal
    }

    func pendingPlan() -> MacPeerRosterPlan? { pending }

    func snapshot() -> MacPeerRosterSnapshot { current }

    /// Persistent mutation requires a fresh complete observation from the
    /// same server, captured under the daemon owner's exclusive write fence.
    /// A parsed snapshot and Boolean alone do not establish provenance;
    /// the future authenticated owner must enforce that external contract.
    func prepare(_ mutation: MacPeerRosterMutation,
                 expected: MacPeerRosterSnapshot,
                 readback: MacPeerPublicInventory.Snapshot? = nil,
                 terminalWriteFenced: Bool = false) -> MacPeerRosterPlan? {
        guard !persistenceBlocked, pending == nil, current == expected, current.revision < UInt64.max else {
            return nil
        }
        if let journal {
            guard terminalWriteFenced, let readback,
                  readback.serverPublicKey == journal.serverPublicKey,
                  readback.peers == current.peers else { return nil }
        }
        var proposed = current.peers
        switch mutation {
        case .enroll(let key):
            guard key != journal?.serverPublicKey, let reservation = MacPeerAddressAllocationPolicy.nextReservation(
                publicKey: key, existing: proposed
            ) else { return nil }
            proposed.append(reservation)
        case .revoke(let exactPeer):
            guard let index = proposed.firstIndex(of: exactPeer) else { return nil }
            proposed.remove(at: index)
        }
        guard let canonical = Self.canonicalRoster(proposed) else { return nil }
        let plan = MacPeerRosterPlan(id: UUID(), before: current, after: canonical)
        guard persist(next: current, pending: plan) else { return nil }
        pending = plan
        return plan
    }

    /// Caller must establish provenance of a complete daemon observation
    /// AFTER fencing the operation against any further asynchronous writes.
    /// A pre-completion readback is not proof of rollback. A stale ID or
    /// divergent roster never releases a reservation.
    /// Raw observations are permitted only for the in-memory policy fixture.
    func resolve(id: UUID, observed: [MacPeerAddressReservation]) -> MacPeerRosterResolution {
        guard pending?.id == id else { return .stale }
        guard journal == nil else { return .unverified }
        return resolveValidated(id: id, observed: observed)
    }

    /// Persistent settlement requires same-server, terminal-fenced public
    /// readback. Caller must keep the exclusive daemon fence across readback
    /// and settlement and never infer fencing from process exit alone.
    func resolve(id: UUID, readback: MacPeerPublicInventory.Snapshot,
                 terminalWriteFenced: Bool) -> MacPeerRosterResolution {
        guard pending?.id == id else { return .stale }
        guard let journal, terminalWriteFenced,
              readback.serverPublicKey == journal.serverPublicKey else { return .unverified }
        return resolveValidated(id: id, observed: readback.peers)
    }

    private func resolveValidated(id: UUID, observed: [MacPeerAddressReservation]) -> MacPeerRosterResolution {
        guard let plan = pending, plan.id == id else { return .stale }
        guard !persistenceBlocked else { return .unverified }
        guard let canonical = Self.canonicalRoster(observed) else { return .unverified }
        let result: MacPeerRosterResolution
        if canonical == plan.after {
            result = .committed
        } else if canonical == plan.before.peers {
            result = .rolledBack
        } else {
            return .unverified
        }
        // Advance even on rollback to invalidate earlier snapshots (ABA).
        let next = MacPeerRosterSnapshot(epoch: current.epoch,
                                         revision: current.revision + 1, peers: canonical)
        guard persist(next: next, pending: nil) else { return .unverified }
        current = next
        pending = nil
        return result
    }

    private func persist(next: MacPeerRosterSnapshot, pending nextPlan: MacPeerRosterPlan?) -> Bool {
        guard let journal else { return true }
        do {
            try journal.replace(expected: MacPeerRosterRecord(
                serverPublicKey: journal.serverPublicKey, current: current, pending: pending),
                with: MacPeerRosterRecord(
                    serverPublicKey: journal.serverPublicKey, current: next, pending: nextPlan))
            return true
        } catch {
            // A failed write could have reached disk. Never dispatch a plan
            // or issue another mutation from this stale actor. Reopen the
            // journal and reconcile with a fenced authoritative daemon.
            persistenceBlocked = true
            return false
        }
    }

    fileprivate static func canonicalRoster(_ peers: [MacPeerAddressReservation])
        -> [MacPeerAddressReservation]? {
        guard peers.count <= MacPeerAddressAllocationPolicy.maxClients else { return nil }
        var keys = Set<String>()
        var slots = Set<UInt8>()
        for peer in peers {
            guard (2...254).contains(Int(peer.slot)),
                  IPhonePairingImportPolicy.validatedPublicKey(peer.publicKey) != nil,
                  keys.insert(peer.publicKey).inserted,
                  slots.insert(peer.slot).inserted else { return nil }
        }
        return peers.sorted { $0.slot < $1.slot }
    }
}


/// Versioned, public-only durable record. No PSK, private key or endpoint.
struct MacPeerRosterRecord: Codable, Equatable, Sendable {
    let version: Int
    let serverPublicKey: String
    let current: MacPeerRosterSnapshot
    let pending: MacPeerRosterPlan?

    init(serverPublicKey: String, current: MacPeerRosterSnapshot, pending: MacPeerRosterPlan?) {
        version = 1
        self.serverPublicKey = serverPublicKey
        self.current = current
        self.pending = pending
    }

    fileprivate var isValid: Bool {
        guard version == 1,
              IPhonePairingImportPolicy.validatedPublicKey(serverPublicKey) != nil,
              !current.peers.contains(where: { $0.publicKey == serverPublicKey }),
              MacPeerRosterCoordinator.canonicalRoster(current.peers) == current.peers else {
            return false
        }
        guard let pending else { return true }
        guard pending.before == current, current.revision < UInt64.max,
              !pending.after.contains(where: { $0.publicKey == serverPublicKey }),
              MacPeerRosterCoordinator.canonicalRoster(pending.after) == pending.after else {
            return false
        }
        let removed = current.peers.filter { !pending.after.contains($0) }
        let added = pending.after.filter { !current.peers.contains($0) }
        if removed.isEmpty, added.count == 1 {
            return MacPeerAddressAllocationPolicy.nextReservation(
                publicKey: added[0].publicKey, existing: current.peers) == added[0]
        }
        return removed.count == 1 && added.isEmpty
    }
}

/// A restart-recoverable journal for a trusted daemon-owned private local
/// directory. All cooperating processes use the same persistent lock inode.
/// The daemon must provision/own the directory (0700) and never unlink the
/// lock file or allow other writers. No live daemon is wired to this yet.
struct MacPeerRosterJournal: Sendable {
    enum JournalError: Error { case unavailable, invalidRecord, conflict, io }
    static let maxBytes = 96 * 1024
    let directory: URL
    let serverPublicKey: String
    private var file: URL { directory.appendingPathComponent("peer-roster-v1.json") }
    private var lockFile: URL { directory.appendingPathComponent("peer-roster-v1.lock") }

    /// Explicit operator bootstrap from a complete authoritative roster.
    /// Never call on automatic restart or in response to a read failure.
    func bootstrap(observed: [MacPeerAddressReservation]) throws {
        guard let canonical = MacPeerRosterCoordinator.canonicalRoster(observed) else {
            throw JournalError.invalidRecord
        }
        let record = MacPeerRosterRecord(serverPublicKey: serverPublicKey,
            current: MacPeerRosterSnapshot(epoch: UUID(), revision: 0, peers: canonical),
            pending: nil)
        try withLock {
            let data = try encode(record)
            // Exclusive creation: never replace an existing (even corrupt)
            // journal. An interrupted first write fails closed on reopen.
            try data.write(to: file, options: .withoutOverwriting)
            try sync(file)
            try sync(directory)
            guard try read() == record else { throw JournalError.io }
        }
    }

    func load() throws -> MacPeerRosterRecord {
        try withLock {
            let record = try read()
            // Also fence a prior interrupted rename/sync before use.
            try sync(file)
            try sync(directory)
            return record
        }
    }

    fileprivate func replace(expected: MacPeerRosterRecord, with next: MacPeerRosterRecord) throws {
        try withLock {
            guard try read() == expected else { throw JournalError.conflict }
            let data = try encode(next)
            try data.write(to: file, options: .atomic)
            // Do not acknowledge a prepared plan until file and directory
            // metadata are synced. A crash before acknowledgement may leave
            // either record; recovery must consult authoritative daemon.
            try sync(file)
            try sync(directory)
            guard try read() == next else { throw JournalError.io }
        }
    }

    private func encode(_ record: MacPeerRosterRecord) throws -> Data {
        guard record.serverPublicKey == serverPublicKey, record.isValid else {
            throw JournalError.invalidRecord
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(record)
        guard data.count <= Self.maxBytes else { throw JournalError.invalidRecord }
        return data
    }

    private func read() throws -> MacPeerRosterRecord {
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let size = (attributes[.size] as? NSNumber)?.intValue,
              size > 0, size <= Self.maxBytes else { throw JournalError.invalidRecord }
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw JournalError.io }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        guard let bytes = try handle.read(upToCount: Self.maxBytes + 1),
              bytes.count == size,
              (try handle.read(upToCount: 1))?.isEmpty != false,
              let record = try? JSONDecoder().decode(MacPeerRosterRecord.self, from: bytes),
              try encode(record) == bytes else { throw JournalError.invalidRecord }
        // Canonical exact-byte roundtrip also rejects unknown/duplicate keys.
        return record
    }

    private func withLock<T>(_ operation: () throws -> T) throws -> T {
        let attrs = try FileManager.default.attributesOfItem(atPath: directory.path)
        guard directory.isFileURL, attrs[.type] as? FileAttributeType == .typeDirectory,
              let permissions = (attrs[.posixPermissions] as? NSNumber)?.intValue,
              let owner = (attrs[.ownerAccountID] as? NSNumber)?.uint32Value,
              owner == UInt32(geteuid()), permissions & 0o777 == 0o700 else { throw JournalError.unavailable }
        let fd = open(lockFile.path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw JournalError.io }
        defer { _ = close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              info.st_uid == geteuid(), info.st_nlink == 1,
              info.st_mode & mode_t(0o777) == mode_t(0o600) else { throw JournalError.unavailable }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw JournalError.conflict }
        return try operation()
    }

    private func sync(_ url: URL) throws {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw JournalError.io }
        defer { _ = close(fd) }
        guard fsync(fd) == 0 else { throw JournalError.io }
    }
}
