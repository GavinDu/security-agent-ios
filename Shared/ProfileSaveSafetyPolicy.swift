import Foundation

/// Pure preflight for native NETunnelProviderManager mutations. A profile
/// re-pair is never safe while an existing PacketTunnel may still be using
/// the old peer and route. Native on-demand may restart that old profile.
enum ProfileSaveSafetyPolicy {
    static func permitsSave(
        hasInstalledManager: Bool,
        nativeDisconnected: Bool,
        nativeOnDemandEnabled: Bool,
        changesPeerOrRoutes: Bool,
        candidateOnDemand: Bool
    ) -> Bool {
        // A verified, empty native inventory permits first-time provisioning.
        // The caller enforces inventory trust independently.
        guard hasInstalledManager else { return true }
        guard nativeDisconnected else { return false }

        // When on-demand is already enabled, only permit disabling it for
        // the SAME peer/routes. Prevent an auto-connect race while replacing
        // peer metadata or changing routing.
        if nativeOnDemandEnabled {
            return !changesPeerOrRoutes && !candidateOnDemand
        }
        return true
    }
}
