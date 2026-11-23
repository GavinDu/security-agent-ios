import Foundation

/// A fail-closed authorization gate for constructing VPN-private WebKit.
/// Connected is a transport state, not proof that the selected native VPN
/// entry matches the public Mac profile currently owned by this app.
///
/// Native provider ID, endpoint and v2 digest comparison are performed by
/// TunnelManager using NativeProfileBindingPolicy (single source of truth).
/// This pure policy is independently executable on Linux without NE APIs.
enum VPNPrivateChatAccessPolicy {
    static func permitsAccess(
        observedConnected: Bool,
        nativeConnected: Bool,
        trustedNativeInventory: Bool,
        verifiedSplitProfile: Bool,
        nativeProfileBound: Bool,
        noPreferenceWriteInFlight: Bool
    ) -> Bool {
        observedConnected && nativeConnected && trustedNativeInventory &&
            verifiedSplitProfile && nativeProfileBound && noPreferenceWriteInFlight
    }
}
