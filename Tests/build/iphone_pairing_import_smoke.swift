import Foundation

@main
struct IPhonePairingImportSmoke {
    static func main() throws {
        let valid = Data(repeating: 0x2a, count: 32).base64EncodedString()
        func payload(_ key: String, version: Int = 1,
                     kind: String = "iphone", endpoint: String? = nil) throws -> String {
            var object: [String: Any] = ["version": version, "kind": kind, "publicKey": key]
            if let endpoint { object["endpoint"] = endpoint }
            return String(decoding: try JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys]
            ), as: UTF8.self)
        }
        let good = try payload(valid)
        precondition(IPhonePairingImportPolicy.decodePublicKey(from: good) == valid)
        precondition(IPhonePairingImportPolicy.validatedPublicKey(valid) == valid)
        precondition(IPhonePairingImportPolicy.decodePublicKey(
            from: try payload(valid, kind: "mac")
        ) == nil)
        precondition(IPhonePairingImportPolicy.decodePublicKey(
            from: try payload(valid, version: 2)
        ) == nil)
        precondition(IPhonePairingImportPolicy.decodePublicKey(
            from: try payload(valid, endpoint: "private.example:51820")
        ) == nil)
        precondition(IPhonePairingImportPolicy.decodePublicKey(
            from: try payload(Data(repeating: 0, count: 32).base64EncodedString())
        ) == nil)
        precondition(IPhonePairingImportPolicy.decodePublicKey(
            from: try payload("invalid-public-key")
        ) == nil)
        precondition(IPhonePairingImportPolicy.decodePublicKey(from: "not json") == nil)
        precondition(IPhonePairingImportPolicy.decodePublicKey(from: "") == nil)
        precondition(IPhonePairingImportPolicy.decodePublicKey(
            from: String(repeating: "a", count: 4_097)
        ) == nil)
        precondition(IPhonePairingImportPolicy.validatedPublicKey(
            valid + "\n"
        ) == nil)
        print("Mac iPhone QR: strict version/kind/endpoint/canonical-key and 4096B bound passed")
    }
}
