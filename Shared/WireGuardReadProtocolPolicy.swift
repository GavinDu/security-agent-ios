import Foundation

/// NEPacketTunnelFlow returns NSNumber protocol families per inner IP frame.
/// Compare NSNumber values BEFORE narrowing to Int32: int32Value can wrap
/// 64-bit malformed values into AF_INET or AF_INET6.
enum WireGuardReadProtocolPolicy {
    static func accepts(_ number: NSNumber, ipv4: Int32, ipv6: Int32) -> Bool {
        number.compare(NSNumber(value: ipv4)) == .orderedSame ||
            number.compare(NSNumber(value: ipv6)) == .orderedSame
    }
}
