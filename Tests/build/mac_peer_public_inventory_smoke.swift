import Foundation

@main
struct MacPeerPublicInventorySmoke {
    static func main() {
        func key(_ n: UInt8) -> String { Data(repeating: n, count: 32).base64EncodedString() }
        let a = key(1), b = key(2), server = key(42)
        func parse(_ peers: String, _ allowed: String, _ publicKey: String? = nil)
            -> MacPeerPublicInventory.Snapshot? {
            MacPeerPublicInventory.decode(expectedServerKey: server,
                publicKeyOutput: Data((publicKey ?? server + "\n").utf8),
                peersOutput: Data(peers.utf8), allowedIPsOutput: Data(allowed.utf8))
        }
        let row = a + "\t10.8.0.2/32 fd86:ea04:1111::2/128\n"
        let second = b + "\tfd86:ea04:1111::3/128 10.8.0.3/32\n"
        precondition(parse(b + "\n" + a + "\n", second + row)?.peers.map(\.slot) == [2, 3])
        precondition(parse("", "")?.peers.isEmpty == true)
        precondition(parse(a + "\n", row, key(43) + "\n") == nil)
        precondition(parse(a + "\n" + b + "\n", row) == nil)
        precondition(parse(a + "\n" + b + "\n", row + row) == nil)
        precondition(parse(a + "\n" + b + "\n", row + b + "\t10.8.0.2/32 fd86:ea04:1111::2/128\n") == nil)
        precondition(parse(a + "\n", String(row.dropLast())) == nil)
        precondition(parse(a + "\n", row.replacingOccurrences(of: "/32", with: "/24")) == nil)
        precondition(parse(a + "\n", row.replacingOccurrences(of: "::2", with: "::3")) == nil)
        precondition(parse(a + "\n", String(repeating: "A", count: MacPeerPublicInventory.maxBytes + 1)) == nil)
        precondition(parse(a + "\n", "utun3\t" + row) == nil)
        print("Mac public peer inventory completeness and address validation passed")
    }
}
