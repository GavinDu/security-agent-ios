import Foundation
import XCTest
@testable import AgentApp

final class WireGuardControlHeadroomPolicyTests: XCTestCase {
    private func message(_ type: UInt8, length: Int) -> Data {
        Data([type, 0, 0, 0] + [UInt8](repeating: 0, count: length - 4))
    }
    private func decide(_ data: Data, _ count: Int) -> WireGuardControlHeadroomPolicy.Decision {
        WireGuardControlHeadroomPolicy.decision(
            datagram: data, pendingSends: count,
            maxPendingSends: 256, reservedControlSlots: 8
        )
    }

    func testEncryptedDataLeavesEightSlotsFreeForHandshakeAndRekey() {
        let payload = message(4, length: 32)
        XCTAssertEqual(decide(payload, 247), .enqueue)
        XCTAssertEqual(decide(payload, 248), .drop)
        XCTAssertEqual(decide(payload, 255), .drop)
        XCTAssertEqual(decide(payload, 256), .drop)
    }

    func testControlPacketsUseHeadroomButNotExceedTotalCapacity() {
        for (type, length) in [(UInt8(1), 148), (2, 92), (3, 64)] {
            let message = message(type, length: length)
            XCTAssertEqual(decide(message, 248), .enqueue)
            XCTAssertEqual(decide(message, 255), .enqueue)
            XCTAssertEqual(decide(message, 256), .drop)
        }
    }

    func testMalformedDatagramsAreNeverPriorityTraffic() {
        for message in [
            Data(), self.message(1, length: 147), self.message(2, length: 91),
            self.message(3, length: 63), self.message(4, length: 31),
            self.message(5, length: 32),
            Data([1, 0, 1, 0] + [UInt8](repeating: 0, count: 144))
        ] {
            XCTAssertEqual(decide(message, 0), .invalid)
        }
        XCTAssertEqual(decide(self.message(1, length: 148), -1), .invalid)
    }
}
