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
}
