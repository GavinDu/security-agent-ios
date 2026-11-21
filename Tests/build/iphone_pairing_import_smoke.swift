import Foundation

@main
struct IPhonePairingImportSmoke {
    static func main() {
        let valid = Data(repeating: 0x2a, count: 32).base64EncodedString()
        func payload(_ key: String, version: Int = 1,
                     kind: String = "iphone", endpoint: String? = nil) -> String {
            var object: [String: Any] = ["version": version, "kind": kind, "publicKey": key]
            if let endpoint { object["endpoint"] = endpoint }
            guard let data = try? JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys]
            ) else {
                preconditionFailure("Invalid fixed test fixture")
            }
            return String(decoding: data, as: UTF8.self)
        }
        let good = payload(valid)
        precondition(IPhonePairingImportPolicy.decodePublicKey(from: good) == valid)
        precondition(IPhonePairingImportPolicy.validatedPublicKey(valid) == valid)
        precondition(IPhonePairingImportPolicy.decodePublicKey(
            from: payload(valid, kind: "mac")
        ) == nil)
        precondition(IPhonePairingImportPolicy.decodePublicKey(
            from: payload(valid, version: 2)
        ) == nil)
        precondition(IPhonePairingImportPolicy.decodePublicKey(
            from: payload(valid, endpoint: "private.example:51820")
        ) == nil)
        precondition(IPhonePairingImportPolicy.decodePublicKey(
            from: payload(Data(repeating: 0, count: 32).base64EncodedString())
        ) == nil)
        precondition(IPhonePairingImportPolicy.decodePublicKey(
            from: payload("invalid-public-key")
        ) == nil)
        // Reject null/extra endpoints and literal/escaped duplicate members.
        for bad in [
            String(good.dropLast()) + #","endpoint":null}"#,
            String(good.dropLast()) + #","endpoint":"evil.test:51820"}"#,
            String(good.dropLast()) + #","publicKey":"bad"}"#,
            String(good.dropLast()) + #","publi\u0063Key":"bad"}"#,
            String(good.dropLast()) + #","kind":"mac"}"#
        ] {
            precondition(IPhonePairingImportPolicy.decodePublicKey(from: bad) == nil)
        }
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
