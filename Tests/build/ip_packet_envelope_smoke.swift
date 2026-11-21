import Foundation

@main
struct IPPacketEnvelopeSmoke {
    static func ipv4(_ count: Int = 32, headerBytes: Int = 20) -> Data {
        precondition(count >= headerBytes && headerBytes >= 20)
        var bytes = [UInt8](repeating: 0, count: count)
        bytes[0] = 0x40 | UInt8(headerBytes / 4)
        bytes[2] = UInt8((count >> 8) & 0xFF)
        bytes[3] = UInt8(count & 0xFF)
        return Data(bytes)
    }

    static func ipv6(_ payloadBytes: Int = 8) -> Data {
        var bytes = [UInt8](repeating: 0, count: payloadBytes + 40)
        bytes[0] = 0x60
        bytes[4] = UInt8((payloadBytes >> 8) & 0xFF)
        bytes[5] = UInt8(payloadBytes & 0xFF)
        return Data(bytes)
    }

    static func main() {
        let v4 = ipv4()
        let v6 = ipv6()
        precondition(IPPacketEnvelope.isValid(v4, family: .ipv4))
        precondition(IPPacketEnvelope.isValid(v6, family: .ipv6))
        precondition(IPPacketEnvelope.isValid(ipv4(20), family: .ipv4))
        precondition(IPPacketEnvelope.isValid(ipv4(28, headerBytes: 24), family: .ipv4))
        precondition(IPPacketEnvelope.isValid(ipv4(65535), family: .ipv4))
        precondition(IPPacketEnvelope.isValid(ipv6(0), family: .ipv6))
        precondition(IPPacketEnvelope.isValid(ipv6(65496), family: .ipv6))
        precondition(!IPPacketEnvelope.isValid(v4, family: .ipv6))
        precondition(!IPPacketEnvelope.isValid(v6, family: .ipv4))
        precondition(!IPPacketEnvelope.isValid(Data(), family: .ipv4))
        precondition(!IPPacketEnvelope.isValid(Data(repeating: 0, count: 65537), family: .ipv6))
        for size in 0..<v4.count {
            precondition(!IPPacketEnvelope.isValid(v4.prefix(size), family: .ipv4))
        }
        for size in 0..<v6.count {
            precondition(!IPPacketEnvelope.isValid(v6.prefix(size), family: .ipv6))
        }
        var broken = [UInt8](v4)
        broken[0] = 0x44
        precondition(!IPPacketEnvelope.isValid(Data(broken), family: .ipv4))
        broken[0] = 0x4F
        precondition(!IPPacketEnvelope.isValid(Data(broken), family: .ipv4))
        broken[0] = 0x45
        broken[3] = 31
        precondition(!IPPacketEnvelope.isValid(Data(broken), family: .ipv4))
        broken[3] = 33
        precondition(!IPPacketEnvelope.isValid(Data(broken), family: .ipv4))
        broken[3] = 32
        broken[2] = 0xFF
        precondition(!IPPacketEnvelope.isValid(Data(broken), family: .ipv4))

        var brokenV6 = [UInt8](v6)
        brokenV6[0] = 0x40
        precondition(!IPPacketEnvelope.isValid(Data(brokenV6), family: .ipv6))
        brokenV6[0] = 0x60
        brokenV6[5] = 9
        precondition(!IPPacketEnvelope.isValid(Data(brokenV6), family: .ipv6))
        brokenV6[5] = 0
        precondition(!IPPacketEnvelope.isValid(Data(brokenV6), family: .ipv6))
        // Exercise malformed data generated deterministically; no unsafe reads.
        var state: UInt32 = 0x51A4D7AB
        for iteration in 0..<1024 {
            let length = iteration % 257
            var bytes = [UInt8](repeating: 0, count: length)
            for index in 0..<length {
                state = 1664525 &* state &+ 1013904223
                bytes[index] = UInt8(truncatingIfNeeded: state >> 16)
            }
            let packet = Data(bytes)
            _ = IPPacketEnvelope.isValid(packet, family: .ipv4)
            _ = IPPacketEnvelope.isValid(packet, family: .ipv6)
        }
        print("IPv4/IPv6 envelope: valid headers, 80 truncations, length/version failures and 1024 deterministic malformed frames passed")
    }
}
