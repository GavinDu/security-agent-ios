import Foundation

@main
struct BoringTunFFIDoneSmoke {
    static func main() {
        precondition(BoringTunFFIDonePolicy.acceptsDoneSize(0))
        for malformed in [-1, 1, 148, 65_600, Int.max] {
            precondition(!BoringTunFFIDonePolicy.acceptsDoneSize(malformed))
        }
        print("Rust WIREGUARD_DONE size=0 ABI invariant: passed")
    }
}
