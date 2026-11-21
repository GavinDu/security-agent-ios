import Foundation

@main
struct LegacyFullTunnelRecoverySmoke {
    static func main() {
        for active in [false, true] {
            for onDemand in [false, true] {
                let split = LegacyFullTunnelRecovery.assess(
                    isFullMode: false, isActive: active, isOnDemandEnabled: onDemand
                )
                precondition(!split.stopActiveSession && !split.disableOnDemand &&
                             !split.blockNewConnection)
                let full = LegacyFullTunnelRecovery.assess(
                    isFullMode: true, isActive: active, isOnDemandEnabled: onDemand
                )
                precondition(full.stopActiveSession == active)
                precondition(full.disableOnDemand == onDemand)
                precondition(full.blockNewConnection)
                // An old app-owned native manager without trusted App Group
                // pairing data must not silently keep a full tunnel alive.
                let orphaned = LegacyFullTunnelRecovery.assess(
                    isFullMode: nil, isActive: active, isOnDemandEnabled: onDemand
                )
                precondition(orphaned == full)
            }
        }
        print("Legacy/full-orphaned VPN recovery: active/inactive, known/unknown and on-demand matrix passed")
    }
}
