import Foundation

@main
struct PeerPSKBindingSmoke {
    static func main() throws {
        func key(_ n: UInt8) -> String { Data(repeating: n, count: 32).base64EncodedString() }
        let server = key(42), client = key(7), secret = Data(repeating: 8, count: 32)
        let txn = UUID(uuidString: "12345678-1234-1234-1234-123456789ABC")!
        let requirement = PeerPSKRequirement(transactionID: txn, clientPublicKey: client)
        func record(_ server: String, _ client: String, _ secret: Data) throws -> Data {
            try JSONSerialization.data(withJSONObject: ["version": 2, "serverPublicKey": server,
                "clientPublicKey": client, "transactionID": txn.uuidString, "presharedKey": secret.base64EncodedString()], options: [.sortedKeys])
        }
        let bound = try record(server, client, secret)
        let absent = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                                                    legacyPresent: false, boundRecord: nil, requirement: nil)
        precondition(absent == nil)
        let selected = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                                                      legacyPresent: false, boundRecord: bound, requirement: requirement)
        precondition(selected == secret)
        for candidate in [nil, Optional(bound)] {
            do {
                _ = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                                                   legacyPresent: true, boundRecord: candidate, requirement: requirement)
                preconditionFailure("unbound legacy PSK accepted")
            } catch PeerPSKBindingPolicy.SelectionError.unboundLegacy {}
        }
        let bad = [try record(key(43), client, secret), try record(server, key(9), secret),
                   try record(server, client, Data(repeating: 0, count: 32)), Data("invalid".utf8)]
        for candidate in bad {
            do {
                _ = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                                                   legacyPresent: false, boundRecord: candidate, requirement: requirement)
                preconditionFailure("invalid bound PSK accepted")
            } catch PeerPSKBindingPolicy.SelectionError.invalidRecord {}
        }
        do {
            _ = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                                               legacyPresent: false, boundRecord: bound + Data([10]), requirement: requirement)
            preconditionFailure("noncanonical PSK accepted")
        } catch PeerPSKBindingPolicy.SelectionError.invalidRecord {}
        do {
            _ = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                legacyPresent: false, boundRecord: nil, requirement: requirement)
            preconditionFailure("required PSK downgraded")
        } catch PeerPSKBindingPolicy.SelectionError.missingRequired {}
        do {
            _ = try PeerPSKBindingPolicy.select(serverPublicKey: server, clientPublicKey: client,
                legacyPresent: false, boundRecord: bound, requirement: nil)
            preconditionFailure("unmarked record accepted")
        } catch PeerPSKBindingPolicy.SelectionError.unexpectedRecord {}
        precondition(!PeerPSKRequirement.permitsOrdinarySave(prior: requirement, priorServer: server,
            candidate: nil, candidateServer: server, nativeRequiresPSK: true, priorVerified: true))
        precondition(!PeerPSKRequirement.permitsOrdinarySave(prior: nil, priorServer: nil,
            candidate: nil, candidateServer: server, nativeRequiresPSK: true, priorVerified: false))
        precondition(PeerPSKRequirement.permitsOrdinarySave(prior: requirement, priorServer: server,
            candidate: requirement, candidateServer: server, nativeRequiresPSK: true, priorVerified: true))
        var staged: Data?
        var inserts = 0
        func stage(_ candidate: Data, _ marker: PeerPSKRequirement = requirement) throws -> PeerPSKBindingPolicy.StageReceipt {
            try PeerPSKBindingPolicy.stageInitial(serverPublicKey: server, requirement: marker, secret: candidate,
                verifyLocalState: {}, readStage: { staged }, insertIfAbsent: { bytes in
                    inserts += 1
                    if staged == nil { staged = bytes }
                })
        }
        let receipt = try stage(secret)
        precondition(receipt.requirement == requirement && receipt.serverPublicKey == server)
        let retry = try stage(secret)
        precondition(retry == receipt && inserts == 1)
        do {
            _ = try stage(Data(repeating: 9, count: 32))
            preconditionFailure("different staged secret accepted")
        } catch PeerPSKBindingPolicy.StageError.conflict {}
        do {
            _ = try stage(secret, PeerPSKRequirement(transactionID: UUID(), clientPublicKey: client))
            preconditionFailure("different transaction accepted")
        } catch PeerPSKBindingPolicy.StageError.conflict {}
        do {
            _ = try stage(Data(repeating: 0, count: 32))
            preconditionFailure("zero secret accepted")
        } catch PeerPSKBindingPolicy.StageError.invalidInput {}
        do {
            _ = try PeerPSKBindingPolicy.stageInitial(serverPublicKey: server, requirement: requirement,
                secret: secret, verifyLocalState: {}, readStage: { nil }, insertIfAbsent: { _ in })
            preconditionFailure("missing persisted winner accepted")
        } catch PeerPSKBindingPolicy.StageError.missingWinner {}
        precondition(inserts == 1)
        print("Peer-bound PSK selection, initial staging and legacy fail-closed policy passed")
    }
}
