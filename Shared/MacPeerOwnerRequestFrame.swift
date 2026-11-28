import Foundation

/// Public wire representation only. Encoding a frame does not authorize it.
/// A trusted owner must independently approve the exact decoded intent.
enum MacPeerOwnerRequestFrame {
    enum Operation: Equatable {
        case enroll
        case revoke(slot: UInt8)
    }

    static let byteCount = 129

    static func encode(requestID: UUID, daemonGeneration: UUID, rosterEpoch: UUID,
                       expectedRevision: UInt64, serverPublicKey: String,
                       clientPublicKey: String, operation: Operation) -> Data? {
        guard expectedRevision < UInt64.max,
              serverPublicKey != clientPublicKey,
              IPhonePairingImportPolicy.validatedPublicKey(serverPublicKey) != nil,
              IPhonePairingImportPolicy.validatedPublicKey(clientPublicKey) != nil,
              let server = Data(base64Encoded: serverPublicKey),
              let client = Data(base64Encoded: clientPublicKey) else { return nil }
        let ids = [requestID, daemonGeneration, rosterEpoch].map { value -> [UInt8] in
            let u = value.uuid
            return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
                    u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
        }
        guard ids.allSatisfy({ $0.contains(where: { $0 != 0 }) }) else { return nil }
        let opcode: UInt8
        let slot: UInt8
        switch operation {
        case .enroll:
            opcode = 1
            slot = 0
        case .revoke(let exactSlot):
            guard (2...254).contains(Int(exactSlot)) else { return nil }
            opcode = 2
            slot = exactSlot
        }
        var bytes = Data([0x53, 0x41, 0x50, 0x4f, 1, opcode, 0, 0])
        for id in ids { bytes.append(contentsOf: id) }
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: expectedRevision >> shift))
        }
        bytes.append(server)
        bytes.append(client)
        bytes.append(slot)
        return bytes.count == byteCount ? bytes : nil
    }
}
