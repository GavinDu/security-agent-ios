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
enum MacPeerRosterMutation: Equatable, Sendable {
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


/// Public intent, not authorization. Never decode a daemon capability from a
/// network request. Only the future trusted, OS-authenticated owner may issue
/// a lease after authorizing this exact intent.
enum MacPeerMutationIntent: Equatable, Sendable {
    case mutate(expected: MacPeerRosterSnapshot, mutation: MacPeerRosterMutation)
    // Explicit request identity is part of the trusted owner's authorization.
    case enroll(requestID: UUID, expected: MacPeerRosterSnapshot, clientPublicKey: String)
    case recover(transactionID: UUID)
}

struct MacPeerMutationLease: Equatable, Sendable {
    let id: UUID
    let daemonGeneration: UUID
    let serverPublicKey: String
    let intent: MacPeerMutationIntent
}

struct MacPeerMutationObservation: Sendable {
    let lease: MacPeerMutationLease
    let transactionID: UUID?
    let inventory: MacPeerPublicInventory.Snapshot
}

/// Trusted in-process adapter contract for the future privileged Rust owner
/// (#27). No implementation may expose this as an unauthenticated RPC.
/// acquire must authenticate the caller, authorize the exact intent, exclude
/// alternate writers and fence earlier operations. A throwing acquire must
/// leave no usable lease and retain containment if acquisition was ambiguous.
/// Both capture methods must
/// capture a complete bounded public inventory from the same verified daemon
/// generation while holding the lease. terminal must additionally fence all
/// writes for the exact transaction, even after cancellation or apply failure.
/// release must preserve containment if outstanding writes cannot be fenced;
/// a later acquire must never bypass that containment. Returning these Swift
/// values alone is not evidence that any of those guarantees hold.
protocol MacPeerMutationOwner: Sendable {
    func acquire(serverPublicKey: String, intent: MacPeerMutationIntent) async throws -> MacPeerMutationLease
    func initialInventory(lease: MacPeerMutationLease) async throws -> MacPeerMutationObservation
    func apply(plan: MacPeerRosterPlan, lease: MacPeerMutationLease) async throws
    func terminalInventory(lease: MacPeerMutationLease, transactionID: UUID) async throws -> MacPeerMutationObservation
    func release(lease: MacPeerMutationLease) async
}

enum MacPeerMutationExecution: Equatable, Sendable {
    case busy, refused, unverified
    case settled(transactionID: UUID, resolution: MacPeerRosterResolution)
    // Public candidate only. No authenticated delivery or activation implied.
    case enrollmentCommitted(MacEnrollmentAddressReceipt)
}

/// Testable orchestration only. The companion UI and PacketTunnel must not
/// instantiate a live owner. This actor prevents reentrant mutation within
/// one executor; cross-process exclusion and authenticated authorization
/// remain the trusted Rust adapter's obligation. Reopen the durable journal
/// under the lease for every operation; never bootstrap during execution.
actor MacPeerMutationExecutor {
    private let journal: MacPeerRosterJournal
    private let owner: any MacPeerMutationOwner
    private var busy = false

    init(journal: MacPeerRosterJournal, owner: any MacPeerMutationOwner) {
        self.journal = journal
        self.owner = owner
    }

    func execute(_ intent: MacPeerMutationIntent) async -> MacPeerMutationExecution {
        guard !busy else { return .busy }
        guard !Task.isCancelled else { return .refused }
        if case let .enroll(requestID, _, clientPublicKey) = intent {
            guard MacEnrollmentAddressReceipt.validID(requestID),
                  clientPublicKey != journal.serverPublicKey,
                  IPhonePairingImportPolicy.validatedPublicKey(clientPublicKey) != nil else {
                return .refused
            }
        }
        busy = true
        defer { busy = false }
        let lease: MacPeerMutationLease
        do {
            lease = try await owner.acquire(serverPublicKey: journal.serverPublicKey, intent: intent)
        } catch { return .refused }
        let result = await underLease(lease, intent: intent)
        // Always release exactly the acquired lease, including errors and
        // cancellation. The trusted owner must quarantine unfenced writes.
        await owner.release(lease: lease)
        return result
    }

    private func underLease(_ lease: MacPeerMutationLease,
                            intent: MacPeerMutationIntent) async -> MacPeerMutationExecution {
        guard lease.serverPublicKey == journal.serverPublicKey, lease.intent == intent,
              lease.id.uuidString != "00000000-0000-0000-0000-000000000000",
              lease.daemonGeneration.uuidString != "00000000-0000-0000-0000-000000000000",
              let coordinator = MacPeerRosterCoordinator(journal: journal) else { return .unverified }
        switch intent {
        case .mutate, .enroll:
            let expected: MacPeerRosterSnapshot
            let mutation: MacPeerRosterMutation
            switch intent {
            case let .mutate(snapshot, delta):
                expected = snapshot
                mutation = delta
            case let .enroll(_, snapshot, clientPublicKey):
                expected = snapshot
                mutation = .enroll(publicKey: clientPublicKey)
            case .recover:
                return .refused
            }
            guard !Task.isCancelled, await coordinator.pendingPlan() == nil,
                  await coordinator.snapshot() == expected else { return .refused }
            guard let before = try? await owner.initialInventory(lease: lease),
                  valid(before, lease: lease, transactionID: nil),
                  !Task.isCancelled else { return .unverified }
            // Prepare must durably succeed before dispatch. Nil may indicate
            // an ambiguous journal write; never interpret it as safe rollback.
            guard let plan = await coordinator.prepare(mutation, expected: expected,
                  readback: before.inventory, terminalWriteFenced: true) else { return .unverified }
            if !Task.isCancelled {
                // Even a thrown apply can have changed the daemon. Never
                // redispatch or infer rollback from an error/exit status.
                do { try await owner.apply(plan: plan, lease: lease) } catch {}
            }
            return await settle(plan, lease: lease, coordinator: coordinator)
        case let .recover(transactionID):
            guard let plan = await coordinator.pendingPlan(), plan.id == transactionID else {
                return .refused
            }
            // Recovery is terminal readback only, never another apply.
            return await settle(plan, lease: lease, coordinator: coordinator)
        }
    }

    private func valid(_ observation: MacPeerMutationObservation,
                       lease: MacPeerMutationLease, transactionID: UUID?) -> Bool {
        observation.lease == lease && observation.transactionID == transactionID &&
        observation.inventory.serverPublicKey == journal.serverPublicKey
    }

    private func settle(_ plan: MacPeerRosterPlan, lease: MacPeerMutationLease,
                        coordinator: MacPeerRosterCoordinator) async -> MacPeerMutationExecution {
        guard let observation = try? await owner.terminalInventory(lease: lease, transactionID: plan.id),
              valid(observation, lease: lease, transactionID: plan.id) else { return .unverified }
        let resolution = await coordinator.resolve(id: plan.id, readback: observation.inventory,
                                                    terminalWriteFenced: true)
        guard resolution == .committed || resolution == .rolledBack else { return .unverified }
        // Issue only under the same lease, after journal settlement and
        // a second exact durable readback. A failure here cannot undo a
        // committed mutation or authorize a second dispatch.
        if resolution == .committed,
           case let .enroll(requestID, expected, clientPublicKey) = lease.intent,
           let record = try? journal.load(),
           let candidate = MacEnrollmentAddressReceipt.candidate(requestID: requestID,
                serverPublicKey: lease.serverPublicKey, clientPublicKey: clientPublicKey,
                expected: expected, plan: plan, settled: record) {
            return .enrollmentCommitted(candidate)
        }
        // Recovery or a lost candidate is NOT a license to enroll again.
        // Durable request/receipt replay is a separate protocol requirement.
        return .settled(transactionID: plan.id, resolution: resolution)
    }
}


/// A versioned public-only enrollment receipt CANDIDATE. WireGuard X25519
/// keys are not signature keys. Canonical bytes and matching context are
/// structural checks, not proof of authenticity, freshness or possession.
/// Do not write a native profile or activate a slot from this value.
struct MacEnrollmentAddressReceipt: Codable, Equatable, Sendable {
    private let version: Int
    private let kind: String
    let requestID: UUID
    let transactionID: UUID
    let serverPublicKey: String
    let clientPublicKey: String
    let rosterEpoch: UUID
    let revision: UInt64
    let slot: UInt8

    static let maxBytes = 2048

    private init(requestID: UUID, transactionID: UUID, serverPublicKey: String,
                 clientPublicKey: String, rosterEpoch: UUID, revision: UInt64, slot: UInt8) {
        version = 1
        kind = "enrollment-committed"
        self.requestID = requestID
        self.transactionID = transactionID
        self.serverPublicKey = serverPublicKey
        self.clientPublicKey = clientPublicKey
        self.rosterEpoch = rosterEpoch
        self.revision = revision
        self.slot = slot
    }

    fileprivate static func validID(_ id: UUID) -> Bool {
        id.uuidString != "00000000-0000-0000-0000-000000000000"
    }

    private var isValid: Bool {
        version == 1 && kind == "enrollment-committed" &&
        Self.validID(requestID) && Self.validID(transactionID) && Self.validID(rosterEpoch) &&
        serverPublicKey != clientPublicKey &&
        IPhonePairingImportPolicy.validatedPublicKey(serverPublicKey) != nil &&
        IPhonePairingImportPolicy.validatedPublicKey(clientPublicKey) != nil &&
        revision > 0 && (2...254).contains(Int(slot))
    }

    /// Host routes are derived exclusively from the allocated slot.
    var publicReservation: MacPeerAddressReservation {
        MacPeerAddressReservation(publicKey: clientPublicKey, slot: slot)
    }

    /// The executor supplies a durably settled record under its trusted
    /// lease. Internal construction is structural and cannot authenticate a
    /// caller-provided record. Refuse rollback, revocation and later revision.
    fileprivate static func candidate(requestID: UUID, serverPublicKey: String,
        clientPublicKey: String, expected: MacPeerRosterSnapshot,
        plan: MacPeerRosterPlan, settled: MacPeerRosterRecord) -> Self? {
        guard plan.before == expected, expected.revision < UInt64.max,
              settled.isValid, settled.serverPublicKey == serverPublicKey,
              settled.pending == nil, settled.current.epoch == expected.epoch,
              settled.current.revision == expected.revision + 1,
              settled.current.peers == plan.after,
              MacPeerRosterCoordinator.canonicalRoster(expected.peers) == expected.peers,
              !expected.peers.contains(where: { $0.publicKey == serverPublicKey }),
              let peer = MacPeerAddressAllocationPolicy.nextReservation(
                publicKey: clientPublicKey, existing: expected.peers),
              plan.after == (expected.peers + [peer]).sorted(by: { $0.slot < $1.slot }) else { return nil }
        let receipt = Self(requestID: requestID, transactionID: plan.id,
            serverPublicKey: serverPublicKey, clientPublicKey: clientPublicKey,
            rosterEpoch: expected.epoch, revision: settled.current.revision, slot: peer.slot)
        return receipt.isValid ? receipt : nil
    }

    func canonicalBytes() -> Data? {
        guard isValid else { return nil }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let bytes = try? encoder.encode(self), bytes.count <= Self.maxBytes else { return nil }
        return bytes
    }

    /// Only an UNTRUSTED candidate. Exact canonical roundtrip rejects
    /// unknown/duplicate fields, alternate spellings and arbitrary routes.
    static func decodeUntrusted(_ bytes: Data) -> Self? {
        guard !bytes.isEmpty, bytes.count <= maxBytes,
              let receipt = try? JSONDecoder().decode(Self.self, from: bytes),
              receipt.canonicalBytes() == bytes else { return nil }
        return receipt
    }

    /// The future authenticated control channel supplies this context from
    /// the exact authorized request and committed transaction, not the
    /// decoded receipt. Durable one-time consumption remains mandatory.
    struct Expected: Equatable, Sendable {
        let requestID: UUID
        let transactionID: UUID
        let serverPublicKey: String
        let clientPublicKey: String
        let rosterEpoch: UUID
        let revision: UInt64
    }

    func matchesUntrustedContext(_ expected: Expected) -> Bool {
        isValid && requestID == expected.requestID && transactionID == expected.transactionID &&
        serverPublicKey == expected.serverPublicKey && clientPublicKey == expected.clientPublicKey &&
        rosterEpoch == expected.rosterEpoch && revision == expected.revision
    }
}
