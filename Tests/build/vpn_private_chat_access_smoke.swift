import Foundation

@main
struct VPNPrivateChatAccessSmoke {
    static func main() {
        func allowed(
            observedConnected: Bool = true,
            nativeConnected: Bool = true,
            trustedNativeInventory: Bool = true,
            verifiedSplitProfile: Bool = true,
            nativeProfileBound: Bool = true,
            noPreferenceWriteInFlight: Bool = true
        ) -> Bool {
            VPNPrivateChatAccessPolicy.permitsAccess(
                observedConnected: observedConnected,
                nativeConnected: nativeConnected,
                trustedNativeInventory: trustedNativeInventory,
                verifiedSplitProfile: verifiedSplitProfile,
                nativeProfileBound: nativeProfileBound,
                noPreferenceWriteInFlight: noPreferenceWriteInFlight
            )
        }
        precondition(allowed())
        precondition(!allowed(observedConnected: false))
        precondition(!allowed(nativeConnected: false))
        precondition(!allowed(trustedNativeInventory: false))
        precondition(!allowed(verifiedSplitProfile: false))
        precondition(!allowed(nativeProfileBound: false))
        precondition(!allowed(noPreferenceWriteInFlight: false))
        precondition(!allowed(observedConnected: false, nativeConnected: false))
        precondition(!allowed(nativeConnected: false, nativeProfileBound: false))
        print("VPN-private WebKit native profile authorization gate passed")
    }
}
