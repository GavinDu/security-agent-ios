import Foundation

@main
struct MacPeerAddressAllocationSmoke {
    static func main() async {
        func key(_ n: UInt8) -> String {
            Data(repeating: n, count: 32).base64EncodedString()
        }
        func inventory(_ peers: [MacPeerAddressReservation], server: String? = nil)
            -> MacPeerPublicInventory.Snapshot {
            let serverKey = server ?? key(42)
            let peerText = peers.map { $0.publicKey + "\n" }.joined()
            let allowedText = peers.map { $0.publicKey + "\t" + $0.ipv4CIDR + " " + $0.ipv6CIDR + "\n" }.joined()
            return MacPeerPublicInventory.decode(expectedServerKey: serverKey,
                publicKeyOutput: Data((serverKey + "\n").utf8),
                peersOutput: Data(peerText.utf8), allowedIPsOutput: Data(allowedText.utf8))!
        }
        let a = MacPeerAddressAllocationPolicy.nextReservation(publicKey: key(1), existing: [])
        precondition(a?.slot == 2)
        precondition(a?.allowedIPs == "10.8.0.2/32, fd86:ea04:1111::2/128")
        let b = MacPeerAddressAllocationPolicy.nextReservation(publicKey: key(2), existing: [a!])
        precondition(b?.slot == 3)
        precondition(b?.allowedIPs == "10.8.0.3/32, fd86:ea04:1111::3/128")
        precondition(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(1), existing: [a!]
        ) == nil, "Same public key may not get a second slot")

        let third = MacPeerAddressReservation(publicKey: key(3), slot: 4)
        precondition(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(5), existing: [third, a!]
        )?.slot == 3)
        precondition(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(5), existing: [a!, third]
        )?.slot == 3, "Input order must not influence slot selection")

        for bad in ["", String(repeating: "A", count: 44),
                    Data(repeating: 0, count: 32).base64EncodedString()] {
            precondition(MacPeerAddressAllocationPolicy.nextReservation(
                publicKey: bad, existing: []
            ) == nil)
        }
        for slot: UInt8 in [0, 1, 255] {
            precondition(MacPeerAddressAllocationPolicy.nextReservation(
                publicKey: key(9), existing: [
                    MacPeerAddressReservation(publicKey: key(1), slot: slot)
                ]
            ) == nil)
        }
        let duplicate = MacPeerAddressReservation(publicKey: key(2), slot: a!.slot)
        precondition(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(9), existing: [a!, duplicate]
        ) == nil)
        precondition(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(9), existing: [a!, a!]
        ) == nil)

        let full = (2...254).map { n in
            MacPeerAddressReservation(publicKey: key(UInt8(n)), slot: UInt8(n))
        }
        precondition(full.count == MacPeerAddressAllocationPolicy.maxClients)
        precondition(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(1), existing: full
        ) == nil, "Fully reserved block must not wrap/reassign a slot")

        let gap = full.filter { $0.slot != 133 }
        precondition(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(1), existing: gap
        )?.slot == 133)
        let coordinator = MacPeerRosterCoordinator(peers: [])!
        let initial = await coordinator.snapshot()
        let k1 = key(1)
        let k2 = key(2)
        async let p1 = coordinator.prepare(.enroll(publicKey: k1), expected: initial)
        async let p2 = coordinator.prepare(.enroll(publicKey: k2), expected: initial)
        let results = await [p1, p2]
        let plans = results.compactMap { $0 }
        precondition(plans.count == 1)
        let first = plans[0]
        let uncertain = await coordinator.resolve(id: first.id, observed: [
            MacPeerAddressReservation(publicKey: key(9), slot: 2)
        ])
        precondition(uncertain == .unverified)
        let refused = await coordinator.prepare(.enroll(publicKey: key(3)), expected: initial)
        precondition(refused == nil)
        let commit = await coordinator.resolve(id: first.id, observed: first.after)
        precondition(commit == .committed)
        let latest = await coordinator.snapshot()
        let stale = await coordinator.prepare(.enroll(publicKey: key(3)), expected: initial)
        precondition(stale == nil)
        let second = await coordinator.prepare(.enroll(publicKey: key(3)), expected: latest)
        precondition(second?.after.last?.slot == 3)
        let rollback = await coordinator.resolve(id: second!.id, observed: latest.peers)
        precondition(rollback == .rolledBack)
        let next = await coordinator.snapshot()
        precondition(next.revision == latest.revision + 1 && next.peers == latest.peers)
        let exact = first.after[0]
        let wrong = await coordinator.prepare(.revoke(
            MacPeerAddressReservation(publicKey: exact.publicKey, slot: 3)
        ), expected: next)
        precondition(wrong == nil)
        let revoke = await coordinator.prepare(.revoke(exact), expected: next)
        precondition(revoke?.after.isEmpty == true)
        let replay = await coordinator.resolve(id: first.id, observed: [])
        precondition(replay == .stale)
        let removed = await coordinator.resolve(id: revoke!.id, observed: [])
        precondition(removed == .committed)
        print("Mac peer address collision-free reservation policy passed")
        print("Mac peer roster serialization and readback transaction policy passed")

        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try! FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let journal = MacPeerRosterJournal(directory: directory, serverPublicKey: key(42))
        precondition(MacPeerRosterCoordinator(journal: journal) == nil)
        try! journal.bootstrap(observed: [])
        let writer = MacPeerRosterCoordinator(journal: journal)!
        let otherWriter = MacPeerRosterCoordinator(journal: journal)!
        let original = await writer.snapshot()
        let missing = await writer.prepare(.enroll(publicKey: key(1)), expected: original)
        precondition(missing == nil)
        let wrongServerRead = await writer.prepare(.enroll(publicKey: key(1)), expected: original,
                                                   readback: inventory([], server: key(43)), terminalWriteFenced: true)
        precondition(wrongServerRead == nil)
        let drift = await writer.prepare(.enroll(publicKey: key(1)), expected: original,
                                        readback: inventory([a!]), terminalWriteFenced: true)
        precondition(drift == nil)
        let proposal = await writer.prepare(.enroll(publicKey: key(1)), expected: original,
                                            readback: inventory([]), terminalWriteFenced: true)
        precondition(proposal != nil)
        let conflict = await otherWriter.prepare(.enroll(publicKey: key(2)), expected: original,
                                                 readback: inventory([]), terminalWriteFenced: true)
        precondition(conflict == nil)
        let reopened = MacPeerRosterCoordinator(journal: journal)!
        let recovered = await reopened.pendingPlan()
        precondition(recovered == proposal)
        let unfenced = await reopened.resolve(id: proposal!.id, observed: [])
        precondition(unfenced == .unverified)
        let wrongSettlement = await reopened.resolve(id: proposal!.id,
            readback: inventory(proposal!.after, server: key(43)), terminalWriteFenced: true)
        precondition(wrongSettlement == .unverified)
        let settled = await reopened.resolve(id: proposal!.id, readback: inventory(proposal!.after),
                                             terminalWriteFenced: true)
        precondition(settled == .committed)
        let verified = try! journal.load()
        precondition(verified.current.peers == proposal!.after && verified.pending == nil)
        precondition(verified.current.revision == original.revision + 1)
        let wrongServerJournal = MacPeerRosterJournal(directory: directory, serverPublicKey: key(43))
        precondition(MacPeerRosterCoordinator(journal: wrongServerJournal) == nil)
        let nextWriter = MacPeerRosterCoordinator(journal: journal)!
        let latestSnapshot = await nextWriter.snapshot()
        let selfPeer = await nextWriter.prepare(.enroll(publicKey: key(42)), expected: latestSnapshot,
                                               readback: inventory(latestSnapshot.peers), terminalWriteFenced: true)
        precondition(selfPeer == nil)
        let nextPlan = await nextWriter.prepare(.revoke(proposal!.after[0]), expected: latestSnapshot,
                                               readback: inventory(latestSnapshot.peers), terminalWriteFenced: true)
        precondition(nextPlan != nil)
        let file = directory.appendingPathComponent("peer-roster-v1.json")
        let pendingBytes = try! Data(contentsOf: file)
        try! Data("invalid".utf8).write(to: file)
        let failed = await nextWriter.resolve(id: nextPlan!.id, readback: inventory([]), terminalWriteFenced: true)
        precondition(failed == .unverified)
        try! pendingBytes.write(to: file)
        let refusedAfterRepair = await nextWriter.resolve(id: nextPlan!.id, readback: inventory([]), terminalWriteFenced: true)
        precondition(refusedAfterRepair == .unverified)
        let recoveredWriter = MacPeerRosterCoordinator(journal: journal)!
        let completed = await recoveredWriter.resolve(id: nextPlan!.id, readback: inventory([]), terminalWriteFenced: true)
        precondition(completed == .committed)
        print("Durable peer roster journal restart and fenced readback passed")
        print("Persistent peer roster fresh same-server inventory gate passed")

        let executorDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try! FileManager.default.createDirectory(at: executorDirectory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: executorDirectory) }
        let executorJournal = MacPeerRosterJournal(directory: executorDirectory, serverPublicKey: key(42))
        try! executorJournal.bootstrap(observed: [])
        let daemon = MutationOwnerFixture(journal: executorJournal)
        let executor = MacPeerMutationExecutor(journal: executorJournal, owner: daemon)
        let initialRecord = try! executorJournal.load()
        let intent = MacPeerMutationIntent.mutate(expected: initialRecord.current, mutation: .enroll(publicKey: key(7)))
        await daemon.setMode(.deny)
        let denied = await executor.execute(intent)
        precondition(denied == .refused)
        await daemon.setMode(.staleInitial)
        let badInitial = await executor.execute(intent)
        precondition(badInitial == .unverified)
        precondition((try! executorJournal.load()).pending == nil)
        await daemon.setMode(.staleTerminal)
        let unknown = await executor.execute(intent)
        precondition(unknown == .unverified)
        let pending = try! executorJournal.load().pending!
        let counts = await daemon.counts()
        precondition(counts.0 == 1 && counts.1 == 2 && counts.2)
        let blocked = await executor.execute(intent)
        precondition(blocked == .refused)
        await daemon.setMode(.normal)
        let wrongRecovery = await executor.execute(.recover(transactionID: UUID()))
        precondition(wrongRecovery == .refused)
        let recoveredResult = await executor.execute(.recover(transactionID: pending.id))
        precondition(recoveredResult == .settled(transactionID: pending.id, resolution: .committed))
        let finalCounts = await daemon.counts()
        precondition(finalCounts.0 == 1 && finalCounts.1 == 5)
        let settledRecord = try! executorJournal.load()
        precondition(settledRecord.pending == nil && settledRecord.current.peers == pending.after)
        print("Fenced peer executor durable dispatch and readback-only recovery passed")

    }
}

private actor MutationOwnerFixture: MacPeerMutationOwner {
    enum Failure: Error { case denied, ambiguous }
    enum Mode { case normal, deny, staleTerminal, applyThenThrow, noWriteThenThrow, staleInitial }
    let journal: MacPeerRosterJournal
    var mode: Mode = .normal
    var peers: [MacPeerAddressReservation] = []
    var applies = 0
    var releases = 0
    var pendingWasDurable = false

    init(journal: MacPeerRosterJournal) { self.journal = journal }
    func setMode(_ mode: Mode) { self.mode = mode }
    func counts() -> (Int, Int, Bool) { (applies, releases, pendingWasDurable) }
    func acquire(serverPublicKey: String, intent: MacPeerMutationIntent) async throws -> MacPeerMutationLease {
        if mode == .deny { throw Failure.denied }
        return MacPeerMutationLease(id: UUID(), daemonGeneration: UUID(), serverPublicKey: serverPublicKey, intent: intent)
    }
    private func observation(_ lease: MacPeerMutationLease, _ transactionID: UUID?) -> MacPeerMutationObservation {
        let key = lease.serverPublicKey
        let peerText = peers.map { $0.publicKey + "\n" }.joined()
        let routes = peers.map { $0.publicKey + "\t" + $0.ipv4CIDR + " " + $0.ipv6CIDR + "\n" }.joined()
        let inventory = MacPeerPublicInventory.decode(expectedServerKey: key,
            publicKeyOutput: Data((key + "\n").utf8), peersOutput: Data(peerText.utf8),
            allowedIPsOutput: Data(routes.utf8))!
        return MacPeerMutationObservation(lease: lease, transactionID: transactionID, inventory: inventory)
    }
    func initialInventory(lease: MacPeerMutationLease) async throws -> MacPeerMutationObservation {
        observation(lease, mode == .staleInitial ? UUID() : nil)
    }
    func apply(plan: MacPeerRosterPlan, lease: MacPeerMutationLease) async throws {
        applies += 1
        pendingWasDurable = (try journal.load().pending == plan)
        if mode == .noWriteThenThrow { throw Failure.ambiguous }
        peers = plan.after
        if mode == .applyThenThrow { throw Failure.ambiguous }
    }
    func terminalInventory(lease: MacPeerMutationLease, transactionID: UUID) async throws -> MacPeerMutationObservation {
        observation(lease, mode == .staleTerminal ? UUID() : transactionID)
    }
    func release(lease: MacPeerMutationLease) async { releases += 1 }
}
