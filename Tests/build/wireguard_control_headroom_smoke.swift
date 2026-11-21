import Foundation

@main
struct WireGuardControlHeadroomSmoke {
    static func packet(_ type: UInt8, length: Int) -> Data {
        Data([type, 0, 0, 0] + [UInt8](repeating: 0, count: length - 4))
    }

    static func main() {
        let initiator = packet(1, length: 148)
        let responder = packet(2, length: 92)
        let cookie = packet(3, length: 64)
        let data = packet(4, length: 32)
        func result(_ message: Data, _ pending: Int,
                    _ limit: Int = 256, _ reserve: Int = 8
        ) -> WireGuardControlHeadroomPolicy.Decision {
            WireGuardControlHeadroomPolicy.decision(
                datagram: message, pendingSends: pending,
                maxPendingSends: limit, reservedControlSlots: reserve
            )
        }
        for pending in [0, 247] {
            precondition(result(data, pending) == .enqueue)
            precondition(result(initiator, pending) == .enqueue)
        }
        for pending in [248, 255] {
            precondition(result(data, pending) == .drop)
            for control in [initiator, responder, cookie] {
                precondition(result(control, pending) == .enqueue)
            }
        }
        for message in [initiator, responder, cookie, data] {
            precondition(result(message, 256) == .drop)
            precondition(result(message, -1) == .invalid)
            precondition(result(message, 257) == .invalid)
            precondition(result(message, 0, 256, 0) == .invalid)
            precondition(result(message, 0, 8, 8) == .invalid)
        }
        precondition(result(data, 2, 3, 1) == .drop)
        precondition(result(initiator, 2, 3, 1) == .enqueue)
        for invalid in [
            Data(), packet(0, length: 32), packet(5, length: 32),
            packet(1, length: 147), packet(2, length: 91),
            packet(3, length: 63), packet(4, length: 31),
            Data([1, 0, 1, 0] + [UInt8](repeating: 0, count: 144))
        ] {
            precondition(result(invalid, 0) == .invalid)
        }
        print("WireGuard control headroom: control, data, malformed and saturation passed")
    }
}
