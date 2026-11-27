import Foundation
import XCTest
@testable import AgentApp

final class MacPeerPublicInventoryTests: XCTestCase {
    private func key(_ byte: UInt8) -> String { Data(repeating: byte, count: 32).base64EncodedString() }

    private func decode(_ peers: String, _ allowed: String, server: String? = nil)
        -> MacPeerPublicInventory.Snapshot? {
        MacPeerPublicInventory.decode(expectedServerKey: key(42),
            publicKeyOutput: Data((server ?? key(42) + "\n").utf8),
            peersOutput: Data(peers.utf8), allowedIPsOutput: Data(allowed.utf8))
    }

    func testCompletePublicInventoryAndEmptyInventory() {
        let a = key(1), b = key(2)
        let result = decode(b + "\n" + a + "\n",
            b + "\tfd86:ea04:1111::3/128 10.8.0.3/32\n" +
            a + "\t10.8.0.2/32 fd86:ea04:1111::2/128\n")
        XCTAssertEqual(result?.peers, [
            MacPeerAddressReservation(publicKey: a, slot: 2),
            MacPeerAddressReservation(publicKey: b, slot: 3)])
        XCTAssertEqual(result?.serverPublicKey, key(42))
        XCTAssertEqual(decode("", "")?.peers, [])
        XCTAssertNil(decode("\n", "\n"))
    }

    func testIncompleteOrInconsistentReadbackRejected() {
        let a = key(1), b = key(2)
        let row = a + "\t10.8.0.2/32 fd86:ea04:1111::2/128\n"
        XCTAssertNil(decode(a + "\n" + b + "\n", row))
        XCTAssertNil(decode(a + "\n", row, server: key(43) + "\n"))
        XCTAssertNil(decode(a + "\n", row, server: ""))
        XCTAssertNil(decode(a + "\n" + a + "\n", row + row))
        XCTAssertNil(decode(a + "\n" + b + "\n", row + row))
        XCTAssertNil(decode(a + "\n" + b + "\n", row +
            b + "\t10.8.0.2/32 fd86:ea04:1111::2/128\n"))
        XCTAssertNil(decode(key(42) + "\n", key(42) + "\t10.8.0.2/32 fd86:ea04:1111::2/128\n"))
        XCTAssertNil(decode(a, row))
        XCTAssertNil(decode(a + "\n", String(row.dropLast())))
        XCTAssertNil(decode(a + "\n\n", row))
    }

    func testInvalidRoutesAndUnexpectedOutputRejected() {
        let a = key(1)
        for addresses in ["(none)", "10.8.0.1/32 fd86:ea04:1111::1/128",
                          "10.8.0.255/32 fd86:ea04:1111::ff/128",
                          "10.8.0.2/24 fd86:ea04:1111::2/128",
                          "10.8.0.2/32 fd86:ea04:1111::3/128",
                          "10.8.0.02/32 fd86:ea04:1111::2/128",
                          "10.8.0.2/32 fd86:ea04:1111::2/128 0.0.0.0/0",
                          "10.8.0.2/32  fd86:ea04:1111::2/128",
                          "10.8.0.2/32", "10.8.0.2/32 fd86:ea04:1111::2/128\tsecret"] {
            XCTAssertNil(decode(a + "\n", a + "\t" + addresses + "\n"), addresses)
        }
        XCTAssertNil(decode(a + "\n", String(repeating: "A", count: MacPeerPublicInventory.maxBytes + 1)))
        XCTAssertNil(decode(a + "\n", "utun3\t" + a + "\t10.8.0.2/32 fd86:ea04:1111::2/128\n"))
    }
}
