import Foundation

@main
struct WireGuardPrivateIdentitySmoke {
    static func main() {
        precondition(!WireGuardPrivateIdentityPolicy.accepts(Data()))
        precondition(!WireGuardPrivateIdentityPolicy.accepts(Data(repeating: 0x1, count: 31)))
        precondition(!WireGuardPrivateIdentityPolicy.accepts(Data(repeating: 0, count: 32)))
        precondition(WireGuardPrivateIdentityPolicy.accepts(Data(repeating: 0x42, count: 32)))
        precondition(!WireGuardPrivateIdentityPolicy.accepts(Data(repeating: 0x42, count: 33)))
        var oneByte = Data(repeating: 0, count: 32)
        oneByte[31] = 1
        precondition(WireGuardPrivateIdentityPolicy.accepts(oneByte))
        print("Stored WireGuard private identity: exact length, all-zero and mixed-byte policies passed")
    }
}
