import Foundation

@main
struct NativeProfileBindingSmoke {
    static func main() {
        let a = Data(repeating: 0x24, count: 32).base64EncodedString()
        let b = Data(repeating: 0x25, count: 32).base64EncodedString()
        let matching = NativeProfileBindingPolicy.metadata(for: a)

        precondition(NativeProfileBindingPolicy.allowsStart(
            metadata: matching, profileDigest: a
        ), "Canonical matching public metadata must be accepted")
        precondition(!NativeProfileBindingPolicy.allowsStart(
            metadata: matching, profileDigest: b
        ), "Native save succeeded, App Group commit failed: reject")
        precondition(!NativeProfileBindingPolicy.allowsStart(
            metadata: NativeProfileBindingPolicy.metadata(for: b), profileDigest: a
        ), "App Group ahead of native VPN profile: reject")
        precondition(!NativeProfileBindingPolicy.allowsStart(
            metadata: ["profileVersion": 1], profileDigest: a
        ), "Unmigrated v1 profile must fail closed")
        precondition(!NativeProfileBindingPolicy.allowsStart(
            metadata: ["profileVersion": 3, "publicProfileDigest": a], profileDigest: a
        ), "Unknown native metadata version must fail closed")
        precondition(!NativeProfileBindingPolicy.allowsStart(
            metadata: ["profileVersion": 2, "publicProfileDigest": 123], profileDigest: a
        ), "Malformed type must fail closed")
        precondition(!NativeProfileBindingPolicy.allowsStart(
            metadata: nil, profileDigest: a
        ))
        precondition(!NativeProfileBindingPolicy.allowsStart(
            metadata: matching, profileDigest: nil
        ))
        precondition(!NativeProfileBindingPolicy.allowsStart(
            metadata: matching, profileDigest: "not-base64"
        ))
        precondition(!NativeProfileBindingPolicy.allowsStart(
            metadata: matching, profileDigest: Data(repeating: 0x22, count: 31).base64EncodedString()
        ))
        precondition(!NativeProfileBindingPolicy.allowsStart(
            metadata: ["profileVersion": 2, "publicProfileDigest": a + " "], profileDigest: a
        ))
        print("Native/App Group VPN binding: exact match, drift, schema and invalid metadata passed")
    }
}
