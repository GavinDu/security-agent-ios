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
    }

    static func validatedPublicKey(_ value: String) -> String? {
        // WireGuard public key Base64 has exactly 44 ASCII bytes.
        // Bound manual paste before Base64 allocation/decoding.
        guard value.utf8.count == 44,
              let bytes = Data(base64Encoded: value),
              bytes.count == 32,
              bytes.base64EncodedString() == value,
              bytes.contains(where: { $0 != 0 }) else {
            return nil
        }
        return value
    }

    /// A camera frame must contain exactly one QR; never guess between peers.
    static func cameraPublicKey(from codes: [String]) -> String? {
        guard codes.count == 1 else { return nil }
        return decodePublicKey(from: codes[0])
    }

    static func decodePublicKey(from text: String) -> String? {
        // Reject oversized pasted JSON before allocating Data or parsing.
        guard !text.isEmpty, text.utf8.count <= maxPayloadBytes else {
            return nil
        }
        let bytes = Data(text.utf8)
        guard bytes.count <= maxPayloadBytes,
              // Reject literal and escaped duplicate keys before Foundation
              // parsers can silently normalize first/last values.
              UniqueFlatJSONObjectPolicy.hasUniqueStringKeys(bytes),
              let object = try? JSONSerialization.jsonObject(with: bytes),
              let dictionary = object as? [String: Any],
              Set(dictionary.keys) == Set(["version", "kind", "publicKey"]),
              let payload = try? JSONDecoder().decode(Payload.self, from: bytes),
              payload.version == 1,
              payload.kind == "iphone" else {
            return nil
        }
        return validatedPublicKey(payload.publicKey)
    }
}
