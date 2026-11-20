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
            }
        }
        print("Legacy full-route migration: active/inactive and on-demand matrix passed")
    }
}
