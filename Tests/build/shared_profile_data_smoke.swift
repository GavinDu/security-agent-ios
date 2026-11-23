import Foundation

@main
struct SharedProfileDataSmoke {
    static func main() {
        precondition(!SharedProfileDataPolicy.acceptsEncodedByteCount(-1))
        precondition(!SharedProfileDataPolicy.acceptsEncodedByteCount(0))
        precondition(SharedProfileDataPolicy.acceptsEncodedByteCount(1))
        precondition(SharedProfileDataPolicy.acceptsEncodedByteCount(4_096))
        precondition(!SharedProfileDataPolicy.acceptsEncodedByteCount(4_097))
        precondition(!SharedProfileDataPolicy.acceptsEncodedByteCount(Int.max))
        precondition(!SharedProfileDataPolicy.accepts(Data()))
        precondition(SharedProfileDataPolicy.accepts(Data(repeating: 0x61, count: 4_096)))
        precondition(!SharedProfileDataPolicy.accepts(Data(repeating: 0x61, count: 4_097)))
        print("Bounded public VPN profile decoder policy: empty/boundary/oversized passed")
    }
}
