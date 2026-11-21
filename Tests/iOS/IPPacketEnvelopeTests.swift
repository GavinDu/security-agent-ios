import Foundation
import XCTest
@testable import AgentApp

final class IPPacketEnvelopeTests: XCTestCase {
    func testIPv4ExactLengthAndVersion() {
        var bytes = [UInt8](repeating: 0, count: 24)
        bytes[0] = 0x46
        bytes[3] = 24
        XCTAssertTrue(IPPacketEnvelope.isValid(Data(bytes), family: .ipv4))
        XCTAssertFalse(IPPacketEnvelope.isValid(Data(bytes), family: .ipv6))
        bytes[3] = 25
        XCTAssertFalse(IPPacketEnvelope.isValid(Data(bytes), family: .ipv4))
        bytes[3] = 24
        bytes[0] = 0x47
        XCTAssertFalse(IPPacketEnvelope.isValid(Data(bytes), family: .ipv4))
    }

    func testIPv6ExactPayloadAndVersion() {
        var bytes = [UInt8](repeating: 0, count: 44)
        bytes[0] = 0x60
        bytes[5] = 4
        XCTAssertTrue(IPPacketEnvelope.isValid(Data(bytes), family: .ipv6))
        XCTAssertFalse(IPPacketEnvelope.isValid(Data(bytes), family: .ipv4))
        bytes[5] = 5
        XCTAssertFalse(IPPacketEnvelope.isValid(Data(bytes), family: .ipv6))
        XCTAssertFalse(IPPacketEnvelope.isValid(Data(bytes.prefix(20)), family: .ipv6))
    }
}
