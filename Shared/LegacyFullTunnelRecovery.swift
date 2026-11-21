import Foundation

/// Pure decision policy for detecting a full-route session inherited from
/// an older app build. The current PacketTunnel refuses new full-mode starts,
/// but an existing extension can outlive its hosting SwiftUI process.
enum LegacyFullTunnelRecovery {
    struct Decision: Equatable {
        let stopActiveSession: Bool
        let disableOnDemand: Bool
        let blockNewConnection: Bool
    }

    static func assess(
        isFullMode: Bool,
        isActive: Bool,
        isOnDemandEnabled: Bool
    ) -> Decision {
        guard isFullMode else {
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
