import Foundation

/// Pure fail-closed decision for an inherited full-route session or a
/// matching app-owned native VPN whose App Group pairing data is unavailable.
/// A previous extension can outlive the hosting SwiftUI app after an upgrade.
enum LegacyFullTunnelRecovery {
    struct Decision: Equatable {
        let stopActiveSession: Bool
        let disableOnDemand: Bool
        let blockNewConnection: Bool
    }

    /// nil means the system VPN exists, but its App Group profile cannot be
    /// verified. An untrusted persisted route must not remain active.
    static func assess(
        isFullMode: Bool?,
        isActive: Bool,
        isOnDemandEnabled: Bool
    ) -> Decision {
        // A positively identified split profile is the only state exempt
        // from startup remediation; unknown is as unsafe as legacy full.
        guard isFullMode != false else {
            return Decision(stopActiveSession: false, disableOnDemand: false,
                            blockNewConnection: false)
        }
        return Decision(
            stopActiveSession: isActive,
            disableOnDemand: isOnDemandEnabled,
            blockNewConnection: true
        )
    }
}
