import Foundation

@main
struct WireGuardReadProtocolSmoke {
    static func main() {
        func accepts(_ value: NSNumber) -> Bool {
            WireGuardReadProtocolPolicy.accepts(value, ipv4: 2, ipv6: 30)
        }
        precondition(accepts(NSNumber(value: Int32(2))), "IPv4 accepted")
        precondition(accepts(NSNumber(value: Int32(30))), "IPv6 accepted")
        precondition(!accepts(NSNumber(value: Int32(0))), "unknown AF refused")
        precondition(!accepts(NSNumber(value: Int32(-1))), "negative refused")
        precondition(!accepts(NSNumber(value: Int32(31))), "unassigned refused")
        precondition(!accepts(NSNumber(value: UInt64(4_294_967_298))), "reject AF_INET modulo alias")
        precondition(!accepts(NSNumber(value: UInt64(4_294_967_326))), "reject AF_INET6 modulo alias")
        precondition(!accepts(NSNumber(value: UInt64.max)), "reject UInt64 max")
        precondition(!accepts(NSNumber(value: Double(2.5))), "reject nonintegral alias")
        precondition(!accepts(NSNumber(value: false)), "reject Boolean false")
        precondition(accepts(NSNumber(value: Double(2.0))), "exact numeric equality accepted")
        print("BoringTun utun AF pre-narrowing validation passed")
    }
}
