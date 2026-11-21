import Foundation

/// Strict, bounded public-data parsing of a scanned Mac Mini WireGuard QR.
/// Does not trust the Mac key; PairingView independently requires the human
/// to confirm its fingerprint out of band before any profile save.
enum MacPairingQRInputPolicy {
    static let maxPayloadBytes = 4_096

    enum ValidationError: Error, Equatable {
        case invalidSchema
        case unsupportedVersion
        case wrongKind
        case invalidPublicKey
    }

    struct ValidatedFields: Equatable {
        let publicKey: String
        let endpoint: String
    }

    private struct Payload: Decodable {
        let version: Int
        let kind: String
        let publicKey: String
        let endpoint: String
    }

    static func decode(_ text: String) throws -> ValidatedFields {
        // Measure UTF-8 bytes BEFORE allocating Data or invoking any JSON
        // parser; iOS QRScanner supplies an untrusted String.
        guard !text.isEmpty, text.utf8.count <= maxPayloadBytes else {
            throw ValidationError.invalidSchema
        }
        let data = Data(text.utf8)
        // Reject duplicate root member names, including Unicode-escaped
        // aliases, before Foundation's JSON parsers normalize the dictionary.
        guard UniqueFlatJSONObjectPolicy.hasUniqueStringKeys(data),
              let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any],
              Set(dictionary.keys) == Set(["version", "kind", "publicKey", "endpoint"]),
              let payload = try? JSONDecoder().decode(Payload.self, from: data) else {
            throw ValidationError.invalidSchema
        }
        guard payload.version == 1 else { throw ValidationError.unsupportedVersion }
        guard payload.kind == "mac" else { throw ValidationError.wrongKind }
        guard !payload.endpoint.isEmpty,
              let bytes = Data(base64Encoded: payload.publicKey),
              bytes.count == 32,
              bytes.base64EncodedString() == payload.publicKey,
              bytes.contains(where: { $0 != 0 }) else {
            throw ValidationError.invalidPublicKey
        }
        return ValidatedFields(publicKey: payload.publicKey, endpoint: payload.endpoint)
    }
}
