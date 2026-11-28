import Foundation
import XCTest
@testable import AgentApp

final class MacPeerAddressAllocationPolicyTests: XCTestCase {
    private func key(_ n: UInt8) -> String {
        Data(repeating: n, count: 32).base64EncodedString()
    }

    private func inventory(_ peers: [MacPeerAddressReservation], server: String? = nil)
        -> MacPeerPublicInventory.Snapshot {
        let serverKey = server ?? key(42)
        let peerText = peers.map { $0.publicKey + "\n" }.joined()
        let allowedText = peers.map {
            $0.publicKey + "\t" + $0.ipv4CIDR + " " + $0.ipv6CIDR + "\n"
        }.joined()
        return MacPeerPublicInventory.decode(expectedServerKey: serverKey,
            publicKeyOutput: Data((serverKey + "\n").utf8),
            peersOutput: Data(peerText.utf8), allowedIPsOutput: Data(allowedText.utf8))!
    }

    func testTwoDifferentCanonicalPeersReceiveDistinctIPv4AndIPv6() {
        let first = MacPeerAddressAllocationPolicy.nextReservation(publicKey: key(1), existing: [])!
        let second = MacPeerAddressAllocationPolicy.nextReservation(publicKey: key(2), existing: [first])!
        XCTAssertEqual(first.allowedIPs, "10.8.0.2/32, fd86:ea04:1111::2/128")
        XCTAssertEqual(second.allowedIPs, "10.8.0.3/32, fd86:ea04:1111::3/128")
        XCTAssertNil(MacPeerAddressAllocationPolicy.nextReservation(publicKey: key(1), existing: [first]))
    }

    func testCorruptOrConflictingRegistryFailsClosed() {
        let first = MacPeerAddressReservation(publicKey: key(1), slot: 2)
        XCTAssertNil(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(3), existing: [first, first]
        ))
        let collision = MacPeerAddressReservation(publicKey: key(2), slot: 2)
        XCTAssertNil(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(3), existing: [first, collision]
        ))
        for badSlot: UInt8 in [0, 1, 255] {
            XCTAssertNil(MacPeerAddressAllocationPolicy.nextReservation(
                publicKey: key(3), existing: [
                    MacPeerAddressReservation(publicKey: key(1), slot: badSlot)
                ]
            ))
        }
        XCTAssertNil(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(3), existing: [
                MacPeerAddressReservation(publicKey: "not-base64", slot: 2)
            ]
        ))
        XCTAssertNil(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: Data(repeating: 0, count: 32).base64EncodedString(), existing: []
        ))
    }

    func testLowestSlotSelectionIndependentOfInputOrderAndExhaustion() {
        let occupied = [
            MacPeerAddressReservation(publicKey: key(10), slot: 2),
            MacPeerAddressReservation(publicKey: key(11), slot: 4)
        ]
        XCTAssertEqual(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(12), existing: occupied
        )?.slot, 3)
        XCTAssertEqual(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(12), existing: occupied.reversed()
        )?.slot, 3)
        let full = (2...254).map {
            MacPeerAddressReservation(publicKey: key(UInt8($0)), slot: UInt8($0))
        }
        XCTAssertNil(MacPeerAddressAllocationPolicy.nextReservation(
            publicKey: key(1), existing: full
        ))
    }

    func testConcurrentEnrollmentAndReadback() async throws {
        let coordinator = try XCTUnwrap(MacPeerRosterCoordinator(peers: []))
        let initial = await coordinator.snapshot()
        let firstKey = key(1)
        let secondKey = key(2)
        async let a = coordinator.prepare(.enroll(publicKey: firstKey), expected: initial)
        async let b = coordinator.prepare(.enroll(publicKey: secondKey), expected: initial)
        let results = await [a, b]
        XCTAssertEqual(results.compactMap { $0 }.count, 1)
        let first = try XCTUnwrap(results.compactMap { $0 }.first)
        XCTAssertEqual(first.after.first?.slot, 2)
        let unknown = await coordinator.resolve(id: first.id, observed: [
            MacPeerAddressReservation(publicKey: key(9), slot: 2)
        ])
        XCTAssertEqual(unknown, .unverified)
        let blocked = await coordinator.prepare(.enroll(publicKey: key(3)), expected: initial)
        XCTAssertNil(blocked)
        let committed = await coordinator.resolve(id: first.id, observed: first.after)
        XCTAssertEqual(committed, .committed)
        let stale = await coordinator.prepare(.enroll(publicKey: key(3)), expected: initial)
        XCTAssertNil(stale)
        let latest = await coordinator.snapshot()
        let second = await coordinator.prepare(.enroll(publicKey: key(3)), expected: latest)
        XCTAssertEqual(second?.after.last?.slot, 3)
        let replay = await coordinator.resolve(id: first.id, observed: first.after)
        XCTAssertEqual(replay, .stale)
    }

    func testExactRevokeAndRollbackInvalidateSnapshot() async throws {
        let one = MacPeerAddressReservation(publicKey: key(1), slot: 2)
        let two = MacPeerAddressReservation(publicKey: key(2), slot: 3)
        let coordinator = try XCTUnwrap(MacPeerRosterCoordinator(peers: [two, one]))
        let before = await coordinator.snapshot()
        XCTAssertEqual(before.peers, [one, two])
        let wrong = await coordinator.prepare(.revoke(
            MacPeerAddressReservation(publicKey: one.publicKey, slot: two.slot)
        ), expected: before)
        XCTAssertNil(wrong)
        let candidate = await coordinator.prepare(.revoke(one), expected: before)
        let plan = try XCTUnwrap(candidate)
        XCTAssertEqual(plan.after, [two])
        let rollback = await coordinator.resolve(id: plan.id, observed: [two, one])
        XCTAssertEqual(rollback, .rolledBack)
        let after = await coordinator.snapshot()
        XCTAssertEqual(after.peers, before.peers)
        XCTAssertEqual(after.revision, before.revision + 1)
        let stale = await coordinator.prepare(.revoke(one), expected: before)
        XCTAssertNil(stale)
        let retry = await coordinator.prepare(.revoke(one), expected: after)
        let valid = try XCTUnwrap(retry)
        let committed = await coordinator.resolve(id: valid.id, observed: [two])
        XCTAssertEqual(committed, .committed)
        let remaining = await coordinator.snapshot()
        XCTAssertEqual(remaining.peers, [two])
    }

    func testCorruptRosterOverflowAndDifferentEpoch() async throws {
        let one = MacPeerAddressReservation(publicKey: key(1), slot: 2)
        XCTAssertNil(MacPeerRosterCoordinator(peers: [one, one]))
        XCTAssertNil(MacPeerRosterCoordinator(peers: [
            MacPeerAddressReservation(publicKey: key(1), slot: 1)
        ]))
        let saturated = try XCTUnwrap(MacPeerRosterCoordinator(peers: [], revision: UInt64.max))
        let s = await saturated.snapshot()
        let overflow = await saturated.prepare(.enroll(publicKey: key(2)), expected: s)
        XCTAssertNil(overflow)
        let first = try XCTUnwrap(MacPeerRosterCoordinator(peers: []))
        let restarted = try XCTUnwrap(MacPeerRosterCoordinator(peers: []))
        let old = await first.snapshot()
        let invalid = await restarted.prepare(.enroll(publicKey: key(2)), expected: old)
        XCTAssertNil(invalid)
    }

    func testDurableRosterRestartAndFencedRecovery() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let journal = MacPeerRosterJournal(directory: directory, serverPublicKey: key(42))
        XCTAssertNil(MacPeerRosterCoordinator(journal: journal))
        try journal.bootstrap(observed: [])
        XCTAssertThrowsError(try journal.bootstrap(observed: []))
        let first = try XCTUnwrap(MacPeerRosterCoordinator(journal: journal))
        let staleWriter = try XCTUnwrap(MacPeerRosterCoordinator(journal: journal))
        let initial = await first.snapshot()
        let candidate = await first.prepare(.enroll(publicKey: key(1)), expected: initial,
                                            readback: inventory([]), terminalWriteFenced: true)
        let plan = try XCTUnwrap(candidate)
        let conflicting = await staleWriter.prepare(.enroll(publicKey: key(2)), expected: initial,
                                                     readback: inventory([]), terminalWriteFenced: true)
        XCTAssertNil(conflicting)
        let restarted = try XCTUnwrap(MacPeerRosterCoordinator(journal: journal))
        let restored = await restarted.pendingPlan()
        XCTAssertEqual(restored, plan)
        let unfenced = await restarted.resolve(id: plan.id, observed: initial.peers)
        XCTAssertEqual(unfenced, .unverified)
        let blocked = await restarted.prepare(.enroll(publicKey: key(2)), expected: initial)
        XCTAssertNil(blocked)
        let mismatch = await restarted.resolve(id: plan.id, readback: inventory([
            MacPeerAddressReservation(publicKey: key(9), slot: 2)
        ]), terminalWriteFenced: true)
        XCTAssertEqual(mismatch, .unverified)
        let committed = await restarted.resolve(id: plan.id, readback: inventory(plan.after), terminalWriteFenced: true)
        XCTAssertEqual(committed, .committed)
        let final = try XCTUnwrap(MacPeerRosterCoordinator(journal: journal))
        let snapshot = await final.snapshot()
        XCTAssertEqual(snapshot.peers, plan.after)
        XCTAssertEqual(snapshot.revision, initial.revision + 1)
        let pending = await final.pendingPlan()
        XCTAssertNil(pending)
        let wrongServer = MacPeerRosterJournal(directory: directory, serverPublicKey: key(43))
        XCTAssertNil(MacPeerRosterCoordinator(journal: wrongServer))
        let next = await final.prepare(.revoke(plan.after[0]), expected: snapshot,
                                       readback: inventory(snapshot.peers), terminalWriteFenced: true)
        let revoke = try XCTUnwrap(next)
        let rolledBack = await final.resolve(id: revoke.id, readback: inventory(snapshot.peers), terminalWriteFenced: true)
        XCTAssertEqual(rolledBack, .rolledBack)
        XCTAssertEqual(try journal.load().current.revision, snapshot.revision + 1)
        try Data("corrupt".utf8).write(to: directory.appendingPathComponent("peer-roster-v1.json"))
        XCTAssertNil(MacPeerRosterCoordinator(journal: journal))
        XCTAssertThrowsError(try journal.bootstrap(observed: []))
    }

    func testDurableRosterRejectsMissingOrOversizedRecordAndUnsafeDirectory() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o755])
        defer { try? FileManager.default.removeItem(at: directory) }
        let journal = MacPeerRosterJournal(directory: directory, serverPublicKey: key(42))
        XCTAssertThrowsError(try journal.bootstrap(observed: []))
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        try journal.bootstrap(observed: [])
        let file = directory.appendingPathComponent("peer-roster-v1.json")
        try Data(repeating: 65, count: MacPeerRosterJournal.maxBytes + 1).write(to: file)
        XCTAssertNil(MacPeerRosterCoordinator(journal: journal))
        try FileManager.default.removeItem(at: file)
        XCTAssertNil(MacPeerRosterCoordinator(journal: journal))
    }

    func testDurableRosterWriteFailureBlocksAndDoesNotBootstrap() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let server = key(42)
        let journal = MacPeerRosterJournal(directory: directory, serverPublicKey: server)
        XCTAssertThrowsError(try journal.bootstrap(observed: [
            MacPeerAddressReservation(publicKey: server, slot: 2)
        ]))
        try journal.bootstrap(observed: [])
        let writer = try XCTUnwrap(MacPeerRosterCoordinator(journal: journal))
        let original = await writer.snapshot()
        let selfPeer = await writer.prepare(.enroll(publicKey: server), expected: original,
                                            readback: inventory([]), terminalWriteFenced: true)
        XCTAssertNil(selfPeer)
        let candidate = await writer.prepare(.enroll(publicKey: key(1)), expected: original,
                                             readback: inventory([]), terminalWriteFenced: true)
        let plan = try XCTUnwrap(candidate)
        let file = directory.appendingPathComponent("peer-roster-v1.json")
        let pendingBytes = try Data(contentsOf: file)
        try Data("invalid".utf8).write(to: file)
        let failed = await writer.resolve(id: plan.id, readback: inventory(plan.after), terminalWriteFenced: true)
        XCTAssertEqual(failed, .unverified)
        let stillPending = await writer.pendingPlan()
        XCTAssertEqual(stillPending, plan)
        // Even after the file is externally repaired, a writer that saw an
        // ambiguous IO failure cannot clear its in-memory blocked state.
        try pendingBytes.write(to: file)
        let refused = await writer.resolve(id: plan.id, readback: inventory(plan.after), terminalWriteFenced: true)
        XCTAssertEqual(refused, .unverified)
        let reopened = try XCTUnwrap(MacPeerRosterCoordinator(journal: journal))
        let resolved = await reopened.resolve(id: plan.id, readback: inventory(plan.after), terminalWriteFenced: true)
        XCTAssertEqual(resolved, .committed)
    }

    func testDurableRosterRejectsUnknownFieldsAndWrongLockMode() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let journal = MacPeerRosterJournal(directory: directory, serverPublicKey: key(42))
        try journal.bootstrap(observed: [])
        let file = directory.appendingPathComponent("peer-roster-v1.json")
        let original = try Data(contentsOf: file)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: original) as? [String: Any])
        object["unexpected"] = true
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: file)
        XCTAssertNil(MacPeerRosterCoordinator(journal: journal))
        try original.write(to: file)
        let lock = directory.appendingPathComponent("peer-roster-v1.lock")
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: lock.path)
        XCTAssertNil(MacPeerRosterCoordinator(journal: journal))
    }

    func testPersistentMutationRequiresSameServerFencedInventoryOnEveryPrepareAndSettlement() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let journal = MacPeerRosterJournal(directory: directory, serverPublicKey: key(42))
        try journal.bootstrap(observed: [])
        let owner = try XCTUnwrap(MacPeerRosterCoordinator(journal: journal))
        let initial = await owner.snapshot()
        let mutation = MacPeerRosterMutation.enroll(publicKey: key(1))
        let missing = await owner.prepare(mutation, expected: initial)
        XCTAssertNil(missing)
        let unfenced = await owner.prepare(mutation, expected: initial, readback: inventory([]))
        XCTAssertNil(unfenced)
        let foreign = await owner.prepare(mutation, expected: initial,
                                         readback: inventory([], server: key(43)), terminalWriteFenced: true)
        XCTAssertNil(foreign)
        let drift = await owner.prepare(mutation, expected: initial, readback: inventory([
            MacPeerAddressReservation(publicKey: key(9), slot: 2)
        ]), terminalWriteFenced: true)
        XCTAssertNil(drift)
        XCTAssertNil(try journal.load().pending)
        let candidate = await owner.prepare(mutation, expected: initial,
                                           readback: inventory([]), terminalWriteFenced: true)
        let plan = try XCTUnwrap(candidate)
        let raw = await owner.resolve(id: plan.id, observed: plan.after)
        XCTAssertEqual(raw, .unverified)
        let wrongServer = await owner.resolve(id: plan.id, readback: inventory(plan.after, server: key(43)),
                                              terminalWriteFenced: true)
        XCTAssertEqual(wrongServer, .unverified)
        let noFence = await owner.resolve(id: plan.id, readback: inventory(plan.after), terminalWriteFenced: false)
        XCTAssertEqual(noFence, .unverified)
        let pending = await owner.pendingPlan()
        XCTAssertEqual(pending, plan)
        let settled = await owner.resolve(id: plan.id, readback: inventory(plan.after), terminalWriteFenced: true)
        XCTAssertEqual(settled, .committed)
        let latest = await owner.snapshot()
        let noFreshObservation = await owner.prepare(.revoke(plan.after[0]), expected: latest)
        XCTAssertNil(noFreshObservation)
        let staleObservation = await owner.prepare(.revoke(plan.after[0]), expected: latest,
                                                  readback: inventory([]), terminalWriteFenced: true)
        XCTAssertNil(staleObservation)
        XCTAssertNil(try journal.load().pending)
    }
}
