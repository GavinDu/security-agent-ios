import Foundation

@main
struct PeerOwnerFrameSmoke {
    static func main() throws {
        let request = UUID(uuidString: "01020304-0506-0708-090A-0B0C0D0E0F10")!
        let generation = UUID(uuidString: "11121314-1516-1718-191A-1B1C1D1E1F20")!
        let epoch = UUID(uuidString: "21222324-2526-2728-292A-2B2C2D2E2F30")!
        let server = Data((49...80).map { UInt8($0) }).base64EncodedString()
        let client = Data((81...112).map { UInt8($0) }).base64EncodedString()
        let revision: UInt64 = 0x8123456789abcdef
        let fixture = try String(contentsOfFile: "Tests/build/peer_owner_request_vectors.hex", encoding: .utf8)
            .split(whereSeparator: { $0.isWhitespace }).map(String.init)
        let operations: [MacPeerOwnerRequestFrame.Operation] = [.enroll, .revoke(slot: 254)]
        precondition(fixture.count == operations.count)
        for (index, operation) in operations.enumerated() {
            let bytes = MacPeerOwnerRequestFrame.encode(requestID: request, daemonGeneration: generation,
                rosterEpoch: epoch, expectedRevision: revision, serverPublicKey: server,
                clientPublicKey: client, operation: operation)!
            precondition(bytes.map { String(format: "%02x", Int($0)) }.joined() == fixture[index])
        }
        let zero = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!
        precondition(MacPeerOwnerRequestFrame.encode(requestID: zero, daemonGeneration: generation,
            rosterEpoch: epoch, expectedRevision: revision, serverPublicKey: server,
            clientPublicKey: client, operation: .enroll) == nil)
        precondition(MacPeerOwnerRequestFrame.encode(requestID: request, daemonGeneration: generation,
            rosterEpoch: epoch, expectedRevision: UInt64.max, serverPublicKey: server,
            clientPublicKey: client, operation: .enroll) == nil)
        precondition(MacPeerOwnerRequestFrame.encode(requestID: request, daemonGeneration: generation,
            rosterEpoch: epoch, expectedRevision: revision, serverPublicKey: server,
            clientPublicKey: server, operation: .enroll) == nil)
        for slot: UInt8 in [0, 1, 255] {
            precondition(MacPeerOwnerRequestFrame.encode(requestID: request, daemonGeneration: generation,
                rosterEpoch: epoch, expectedRevision: revision, serverPublicKey: server,
                clientPublicKey: client, operation: .revoke(slot: slot)) == nil)
        }
        print("Swift/Rust shared peer owner request golden vectors passed")
    }
}
