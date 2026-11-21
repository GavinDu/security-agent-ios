import Foundation

@main
struct BoringTunKeyInputSmoke {
    static func main() {
        let secret = Data(repeating: 0x2A, count: 32)
        let peer = Data(repeating: 0x19, count: 32).base64EncodedString()
        let goodPSK = Data(repeating: 0, count: 32)
        func accepts(_ secret: Data, _ peer: String, _ psk: Data? = nil) -> Bool {
            BoringTunKeyInputPolicy.accepts(
                privateKey: secret, serverPublicKey: peer, presharedKey: psk
            )
        }

        precondition(accepts(secret, peer))
        precondition(accepts(secret, peer, goodPSK))
        precondition(!accepts(Data(), peer))
        precondition(!accepts(Data(repeating: 7, count: 31), peer))
        precondition(!accepts(Data(repeating: 7, count: 33), peer))
        precondition(!accepts(Data(repeating: 0, count: 32), peer))
        precondition(!accepts(secret, ""))
        precondition(!accepts(secret, "not base64"))
        precondition(!accepts(secret, Data(repeating: 0, count: 32).base64EncodedString()))
        precondition(!accepts(secret, Data(repeating: 0x19, count: 31).base64EncodedString()))
        precondition(!accepts(secret, peer + "\n"))
        precondition(!accepts(secret, " " + peer))
        precondition(!accepts(secret, peer + " "))
        precondition(!accepts(secret, peer, Data(repeating: 1, count: 31)))
        precondition(!accepts(secret, peer, Data(repeating: 1, count: 33)))
        precondition(accepts(secret, peer, Data(repeating: 1, count: 32)))
        print("Rust BoringTun Swift FFI keys: exact sizes, canonical public Base64 and nonzero key passed")
    }
}
