import Foundation

@main
struct MacPeerAddressAllocationSmoke {
    static func main() async {
        func key(_ n: UInt8) -> String {
            Data(repeating: n, count: 32).base64EncodedString()
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
        let proposal = await writer.prepare(.enroll(publicKey: key(1)), expected: original)
        precondition(proposal != nil)
        let conflict = await otherWriter.prepare(.enroll(publicKey: key(2)), expected: original)
        precondition(conflict == nil)
        let reopened = MacPeerRosterCoordinator(journal: journal)!
        let recovered = await reopened.pendingPlan()
        precondition(recovered == proposal)
        let unfenced = await reopened.resolve(id: proposal!.id, observed: [])
        precondition(unfenced == .unverified)
        let settled = await reopened.resolve(id: proposal!.id, observed: proposal!.after,
                                             terminalWriteFenced: true)
        precondition(settled == .committed)
        let verified = try! journal.load()
        precondition(verified.current.peers == proposal!.after && verified.pending == nil)
        precondition(verified.current.revision == original.revision + 1)
        let wrong = MacPeerRosterJournal(directory: directory, serverPublicKey: key(43))
        precondition(MacPeerRosterCoordinator(journal: wrong) == nil)
        print("Durable peer roster journal restart and fenced readback passed")
    }
}
