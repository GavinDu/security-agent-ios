import Foundation

/// Boundary between a verified Rust BoringTun decrypted IP packet and the
/// system's NEPacketTunnelFlow. A rejected local write is NOT an unauthenticated
/// remote datagram error; it must terminate the misleading connected session.
/// Testable without NetworkExtension or a signed physical iPhone.
enum WireGuardInnerPacketDelivery {
    enum DeliveryError: Error, Equatable {
        case writeRejected
    }

    /// Returns false only for an invalid decrypted IP envelope, which is
    /// safely discarded without touching the system utun interface. A valid
    /// envelope is submitted exactly once, and a write rejection throws.
    @discardableResult
    static func deliver(
        _ packet: Data,
        family: IPPacketFamily,
        write: (Data) -> Bool
    ) throws -> Bool {
        guard IPPacketEnvelope.isValid(packet, family: family) else {
            return false
        }
        guard write(packet) else {
            throw DeliveryError.writeRejected
        }
        return true
    }
}
