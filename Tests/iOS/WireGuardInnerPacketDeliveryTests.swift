import Foundation
import XCTest
@testable import AgentApp

final class WireGuardInnerPacketDeliveryTests: XCTestCase {
    private func validIPv4() -> Data {
        var packet = Data(repeating: 0, count: 20)
        packet[0] = 0x45
        packet[3] = 20
        return packet
    }

    private func validIPv6() -> Data {
        var packet = Data(repeating: 0, count: 40)
        packet[0] = 0x60
        return packet
    }

    func testBothIPFamiliesAcceptExactlyOneLocalWrite() throws {
        for (family, packet) in [
            (IPPacketFamily.ipv4, validIPv4()),
            (IPPacketFamily.ipv6, validIPv6())
        ] {
            var submitted = 0
            let result = try WireGuardInnerPacketDelivery.deliver(
                packet, family: family
            ) { data in
                submitted += 1
                return data == packet
            }
            XCTAssertTrue(result)
            XCTAssertEqual(submitted, 1)
        }
    }

    func testSystemTunRefusesValidDecryptedFrameAndMustStopSession() {
        for (family, packet) in [
            (IPPacketFamily.ipv4, validIPv4()),
            (IPPacketFamily.ipv6, validIPv6())
        ] {
            var submitted = 0
            XCTAssertThrowsError(try WireGuardInnerPacketDelivery.deliver(
                packet, family: family
            ) { _ in
                submitted += 1
                return false
            }) { error in
                XCTAssertEqual(
                    error as? WireGuardInnerPacketDelivery.DeliveryError,
                    .writeRejected
                )
            }
            XCTAssertEqual(submitted, 1)
        }
    }

    func testMalformedPacketsNeverTouchTheSystemTun() throws {
        for family in [IPPacketFamily.ipv4, IPPacketFamily.ipv6] {
            let malformed = Data(repeating: 0, count: 19)
            let result = try WireGuardInnerPacketDelivery.deliver(
                malformed, family: family
            ) { _ in
                XCTFail("Malformed decrypted data must not reach packetFlow")
                return true
            }
            XCTAssertFalse(result)
        }
    }
}
