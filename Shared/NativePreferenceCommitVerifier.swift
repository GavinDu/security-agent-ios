import Foundation

/// Public-only snapshot of system NetworkExtension preferences AFTER a native
/// reload. A successful load callback is insufficient proof of saved state.
struct NativePreferenceCommitSnapshot {
    let providerBundleIdentifier: String?
    let serverAddress: String?
    let metadata: [String: Any]?
    let isEnabled: Bool
    let isOnDemandEnabled: Bool
    let onDemandRuleCount: Int
}

/// Keep public App Group metadata uncommitted until the system VPN profile
/// agrees with the intended peer and the exact on-demand policy.
enum NativePreferenceCommitVerifier {
    static func matches(
        _ native: NativePreferenceCommitSnapshot,
        expectedBundleID: String,
        expectedServerAddress: String,
        expectedProfileDigest: String,
        expectedOnDemand: Bool
    ) -> Bool {
        guard native.providerBundleIdentifier == expectedBundleID,
              native.serverAddress == expectedServerAddress,
              native.isEnabled,
              native.isOnDemandEnabled == expectedOnDemand,
              native.onDemandRuleCount == (expectedOnDemand ? 1 : 0) else {
            return false
        }
        return NativeProfileBindingPolicy.allowsStart(
            metadata: native.metadata,
            profileDigest: expectedProfileDigest
        )
    }
}
