import Foundation

@main
struct NativePreferenceCommitVerifierSmoke {
    static func main() {
        let digest = Data(repeating: 0x39, count: 32).base64EncodedString()
        let expectedID = "com.example.securityagent.PacketTunnel"
        let expectedEndpoint = "home.example.org:51820"
        let metadata = NativeProfileBindingPolicy.metadata(for: digest)

        func check(_ candidate: NativePreferenceCommitSnapshot, onDemand: Bool = false) -> Bool {
            NativePreferenceCommitVerifier.matches(
                candidate,
                expectedBundleID: expectedID,
                expectedServerAddress: expectedEndpoint,
                expectedProfileDigest: digest,
                expectedOnDemand: onDemand
            )
        }
        func state(
            id: String? = "com.example.securityagent.PacketTunnel",
            endpoint: String? = "home.example.org:51820",
            settings: [String: Any]? = nil,
            enabled: Bool = true,
            demand: Bool = false,
            rules: Int = 0,
            connectRule: Bool = false
        ) -> NativePreferenceCommitSnapshot {
            NativePreferenceCommitSnapshot(
                providerBundleIdentifier: id, serverAddress: endpoint,
                metadata: settings ?? metadata, isEnabled: enabled,
                isOnDemandEnabled: demand, onDemandRuleCount: rules,
                onDemandUsesConnectRule: connectRule
            )
        }
        precondition(check(state()), "Valid reloaded profile must be committed")
        precondition(!check(state(id: "wrong.bundle")), "Wrong provider accepted")
        precondition(!check(state(endpoint: "evil.example.org:51820")), "Wrong endpoint accepted")
        precondition(!check(state(settings: ["profileVersion": 1])), "Old schema accepted")
        precondition(!check(state(settings: NativeProfileBindingPolicy.metadata(
            for: Data(repeating: 0x13, count: 32).base64EncodedString()
        ))), "Stale native profile digest accepted")
        precondition(!check(state(enabled: false)), "Disabled profile accepted")
        precondition(!check(state(demand: true, rules: 1)), "Unexpected on-demand enabled")
        precondition(!check(state(rules: 1)), "Unexpected on-demand rule")
        precondition(!check(state(demand: true, rules: 1), onDemand: true),
                     "Wrong on-demand rule type must not be treated as Connect")
        precondition(check(state(demand: true, rules: 1, connectRule: true), onDemand: true))
        precondition(!check(state(demand: true, rules: 0), onDemand: true))
        precondition(!check(state(demand: true, rules: 2), onDemand: true))
        precondition(!check(state(demand: false), onDemand: true))
        precondition(!check(state(id: nil)))
        precondition(!check(state(endpoint: nil)))
        print("Native preference commit verification: matching, stale, invalid and on-demand rules passed")
    }
}
