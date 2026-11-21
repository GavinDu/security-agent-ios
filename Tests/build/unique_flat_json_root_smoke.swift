import Foundation

@main
struct UniqueFlatJSONObjectSmoke {
    static func main() throws {
        let publicKey = Data(repeating: 0x2A, count: 32).base64EncodedString()
        let valid = #"{"version":1,"kind":"mac","publicKey":"KEY","endpoint":"home.example.test:51820"}"#
            .replacingOccurrences(of: "KEY", with: publicKey)
        func permits(_ text: String) -> Bool {
            UniqueFlatJSONObjectPolicy.hasUniqueStringKeys(Data(text.utf8))
        }
        precondition(permits(valid))
        let parsed = try MacPairingQRInputPolicy.decode(valid)
        precondition(parsed.publicKey == publicKey)

        let dup = String(valid.dropLast()) +
            #","endpoint":"evil.example.test:51820"}"#
        let escapedAlias = String(valid.dropLast()) +
            #","endp\u006fint":"evil.example.test:51820"}"#
        let dupKey = String(valid.dropLast()) +
            #","publicKey":"AAAA"}"#
        let escapedKey = String(valid.dropLast()) +
            #","publi\u0063Key":"AAAA"}"#

        for bad in [
            dup, escapedAlias, dupKey, escapedKey,
            valid + "garbage",
            String(valid.dropLast()), // Unterminated object
            #"{"version":1,"kind":{"mac":"bad"},"publicKey":"key","endpoint":"host:1"}"#,
            #"{"version":1,"kind":"mac","publicKey":"key","endpoint":"host:1",}"#,
            #"{"version":1,"kind":"mac","publicKey":"key","endpoint":"host:1","endpoint":false}"#,
            #"{"kind":"mac""#,
            #"[]"#,
            #"{}"#
        ] {
            precondition(!permits(bad), "Invalid or ambiguous flat QR accepted")
            do {
                _ = try MacPairingQRInputPolicy.decode(bad)
                preconditionFailure("Duplicate/malformed scanned QR accepted")
            } catch {
                // The public input gate must fail before profile trust.
            }
        }
        print("Scanned Mac QR duplicate key, Unicode alias, malformed scalar and EOF rejection passed")
    }
}
