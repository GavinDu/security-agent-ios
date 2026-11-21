import Foundation

/// Pure input validation for the non-camera Mac Mini iPhone pairing flow.
/// This accepts only public key material; it never imports secrets or server
/// endpoints from an untrusted iPhone QR.
enum IPhonePairingImportPolicy {
    static let maxPayloadBytes = 4_096

    private struct Payload: Decodable {
        let version: Int
        let kind: String
        let publicKey: String
        let endpoint: String?
    }

    static func validatedPublicKey(_ value: String) -> String? {
        guard let bytes = Data(base64Encoded: value),
              bytes.count == 32,
              bytes.base64EncodedString() == value,
              bytes.contains(where: { $0 != 0 }) else {
            return nil
        }
        return value
    }

    static func decodePublicKey(from text: String) -> String? {
        let bytes = Data(text.utf8)
        guard !bytes.isEmpty, bytes.count <= maxPayloadBytes,
              let payload = try? JSONDecoder().decode(Payload.self, from: bytes),
              payload.version == 1,
              payload.kind == "iphone",
              payload.endpoint == nil else {
            return nil
        }
        return validatedPublicKey(payload.publicKey)
    }
}
