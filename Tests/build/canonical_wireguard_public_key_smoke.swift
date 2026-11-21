import Foundation

@main
struct CanonicalWireGuardPublicKeySmoke {
    static func main() {
        let valid = Data(repeating: 0x2A, count: 32).base64EncodedString()
        precondition(CanonicalWireGuardPublicKeyPolicy.accepts(valid))
        for bad in [
            "", "not Base64",
            Data(repeating: 0, count: 32).base64EncodedString(),
            Data(repeating: 7, count: 31).base64EncodedString(),
            Data(repeating: 7, count: 33).base64EncodedString(),
            String(valid.dropLast()), valid + "\n", " " + valid,
            valid + " ", valid.replacingOccurrences(of: "+", with: "-"),
            valid.replacingOccurrences(of: "/", with: "_")
        ] {
            if bad != valid {
                precondition(!CanonicalWireGuardPublicKeyPolicy.accepts(bad))
            }
        }
        precondition(!CanonicalWireGuardPublicKeyPolicy.accepts(
            String(repeating: "A", count: 44)
        ))
        print("Server WireGuard public key: bounded canonical nonzero representation passed")
    }
}
