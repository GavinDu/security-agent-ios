import Foundation

@main
struct ProfileSaveSafetySmoke {
    static func main() {
        // Verified empty native inventory: first pairing is permitted.
        precondition(ProfileSaveSafetyPolicy.permitsSave(
            hasInstalledManager: false, nativeDisconnected: false,
            nativeOnDemandEnabled: false, changesPeerOrRoutes: true,
            candidateOnDemand: false
        ))
        // Existing native profile cannot be overwritten while connecting,
        // connected, reasserting, or disconnecting.
        for onDemand in [false, true] {
            for changed in [false, true] {
                precondition(!ProfileSaveSafetyPolicy.permitsSave(
                    hasInstalledManager: true, nativeDisconnected: false,
                    nativeOnDemandEnabled: onDemand, changesPeerOrRoutes: changed,
                    candidateOnDemand: false
                ))
            }
        }
        // Explicit disconnect and disabled native on-demand permit re-pairing.
        precondition(ProfileSaveSafetyPolicy.permitsSave(
            hasInstalledManager: true, nativeDisconnected: true,
            nativeOnDemandEnabled: false, changesPeerOrRoutes: true,
            candidateOnDemand: false
        ))
        // Existing OS on-demand may be disabled safely, not used to change peer
        // or routes and not silently retained/re-enabled.
        precondition(ProfileSaveSafetyPolicy.permitsSave(
            hasInstalledManager: true, nativeDisconnected: true,
            nativeOnDemandEnabled: true, changesPeerOrRoutes: false,
            candidateOnDemand: false
        ))
        for changed in [false, true] {
            precondition(!ProfileSaveSafetyPolicy.permitsSave(
                hasInstalledManager: true, nativeDisconnected: true,
                nativeOnDemandEnabled: true, changesPeerOrRoutes: changed,
                candidateOnDemand: true
            ))
        }
        precondition(!ProfileSaveSafetyPolicy.permitsSave(
            hasInstalledManager: true, nativeDisconnected: true,
            nativeOnDemandEnabled: true, changesPeerOrRoutes: true,
            candidateOnDemand: false
        ))
        print("Native VPN session-aware profile save policy: passed")
    }
}
