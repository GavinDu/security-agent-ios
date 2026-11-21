import Foundation

@main
struct MacPairingQRInputSmoke {
    static func main() throws {
        let key = Data(repeating: 0x2a, count: 32).base64EncodedString()
        func json(_ key: String, version: Int = 1, kind: String = "mac",
                  endpoint: String? = "home.example.test:51820",
                  extra: Bool = false) -> String {
            var object: [String: Any] = [
                "version": version, "kind": kind, "publicKey": key
            ]
            if let endpoint { object["endpoint"] = endpoint }
            if extra { object["unexpected"] = "not-accepted" }
            let bytes = try! JSONSerialization.data(
                withJSONObject: object, options: [.sortedKeys]
            )
            return String(decoding: bytes, as: UTF8.self)
        }
        let valid = json(key)
        let fields = try MacPairingQRInputPolicy.decode(valid)
        precondition(fields.publicKey == key)
        precondition(fields.endpoint == "home.example.test:51820")
        let bad: [String] = [
            json(key, version: 2),
            json(key, kind: "iphone"),
            json(key, endpoint: nil),
            json(key, endpoint: ""),
            json(key, extra: true),
            json("bad"),
            json(key + "\n"),
            json(Data(repeating: 0, count: 32).base64EncodedString()),
            "not json", "[]", "",
            String(repeating: "x", count: 4_097),
            String(repeating: "💥", count: 1_200)
        ]
        for item in bad {
            do {
                _ = try MacPairingQRInputPolicy.decode(item)
                preconditionFailure("Untrusted Mac QR unexpectedly accepted")
            } catch MacPairingQRInputPolicy.ValidationError.invalidSchema {
                // Expected malformed or oversize JSON.
            } catch MacPairingQRInputPolicy.ValidationError.unsupportedVersion {
            } catch MacPairingQRInputPolicy.ValidationError.wrongKind {
            } catch MacPairingQRInputPolicy.ValidationError.invalidPublicKey {
            }
        }
        print("Mac QR scan: 4KiB bound, strict schema, canonical nonzero server key passed")
    }
}
