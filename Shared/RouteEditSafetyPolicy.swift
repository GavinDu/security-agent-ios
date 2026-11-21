import Foundation

/// Pure app-side safety gate for editing VPN route settings. A stop request
/// is asynchronous: saving route preferences during an active tunnel can
/// race existing packet routes or a system on-demand reconnection.
enum RouteEditSafetyPolicy {
    static func permitsEdit(
        nativeDisconnected: Bool,
        nativeOnDemandEnabled: Bool,
        saveInFlight: Bool
    ) -> Bool {
        nativeDisconnected && !nativeOnDemandEnabled && !saveInFlight
    }
}
