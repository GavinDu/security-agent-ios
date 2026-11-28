import Foundation

@main
struct PeerPSKBindingSmoke {
    static func main() throws {
        func key(_ n: UInt8) -> String { Data(repeating: n, count: 32).base64EncodedString() }
        let server = key(42), client = key(7), secret = Data(repeating: 8, count: 32)
        func record(_ server: String, _ client: String, _ secret: Data) throws -> Data {
            try JSONSerialization.data(withJSONObject: ["version": 1, "serverPublicKey": server,
                "clientPublicKey": client, "presharedKey": secret.base64EncodedString()], options: [.sortedKeys])
        }
        let bound = try record(server, client, secret)
        let absent = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                                                    legacyPresent: false, boundRecord: nil)
        precondition(absent == nil)
        let selected = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                                                      legacyPresent: false, boundRecord: bound)
        precondition(selected == secret)
        for candidate in [nil, Optional(bound)] {
            do {
                _ = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                                                   legacyPresent: true, boundRecord: candidate)
                preconditionFailure("unbound legacy PSK accepted")
            } catch PeerPSKBindingPolicy.SelectionError.unboundLegacy {}
        }
        let bad = [try record(key(43), client, secret), try record(server, key(9), secret),
                   try record(server, client, Data(repeating: 0, count: 32)), Data("invalid".utf8)]
        for candidate in bad {
            do {
                _ = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                                                   legacyPresent: false, boundRecord: candidate)
                preconditionFailure("invalid bound PSK accepted")
            } catch PeerPSKBindingPolicy.SelectionError.invalidRecord {}
        }
        do {
            _ = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                                               legacyPresent: false, boundRecord: bound + Data([10]))
            preconditionFailure("noncanonical PSK accepted")
        } catch PeerPSKBindingPolicy.SelectionError.invalidRecord {}
        print("Peer-bound PSK selection and legacy fail-closed policy passed")
    }
}
