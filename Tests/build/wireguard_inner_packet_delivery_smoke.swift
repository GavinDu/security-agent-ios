import Foundation

@main
struct WireGuardInnerPacketDeliverySmoke {
    static func main() throws {
        var ipv4 = Data(repeating: 0, count: 20)
        ipv4[0] = 0x45 // IPv4, five 32-bit header words
        ipv4[2] = 0
        ipv4[3] = 20 // exact total length
        var ipv6 = Data(repeating: 0, count: 40)
        ipv6[0] = 0x60 // IPv6, zero payload
        let cases: [(IPPacketFamily, Data)] = [(.ipv4, ipv4), (.ipv6, ipv6)]

        for (family, packet) in cases {
            var calls = 0
            let accepted = try WireGuardInnerPacketDelivery.deliver(
                packet, family: family
            ) { written in
                calls += 1
                return written == packet
            }
            precondition(accepted && calls == 1)

            calls = 0
            do {
                _ = try WireGuardInnerPacketDelivery.deliver(packet, family: family) { _ in
                    calls += 1
                    return false
                }
                preconditionFailure("A valid local utun write rejection must be fatal")
            } catch WireGuardInnerPacketDelivery.DeliveryError.writeRejected {
                precondition(calls == 1)
            }

            calls = 0
            var malformed = packet
            malformed[0] = 0
            let discarded = try WireGuardInnerPacketDelivery.deliver(
                malformed, family: family
            ) { _ in
                calls += 1
                return true
            }
            precondition(!discarded && calls == 0)
        }

        var oversized = Data(repeating: 0, count: IPPacketEnvelope.maxInnerBytes + 1)
        oversized[0] = 0x45
        let didDeliverOversized = try WireGuardInnerPacketDelivery.deliver(
            oversized, family: .ipv4
        ) { _ in
            preconditionFailure("An oversized malformed packet must never reach utun")
        }
        precondition(!didDeliverOversized)
        print("Rust decrypted packet to iOS utun write/failure policy passed")
    }
}
