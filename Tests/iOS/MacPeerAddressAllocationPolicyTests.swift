import Foundation
import XCTest
@testable import AgentApp

final class MacPeerAddressAllocationPolicyTests: XCTestCase {
    private func key(_ n: UInt8) -> String {
        Data(repeating: n, count: 32).base64EncodedString()
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
}
