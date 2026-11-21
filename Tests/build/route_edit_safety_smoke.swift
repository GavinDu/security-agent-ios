import Foundation

@main
struct RouteEditSafetySmoke {
    static func main() {
        var allowed = 0
        for disconnected in [false, true] {
            for onDemand in [false, true] {
                for busy in [false, true] {
                    let result = RouteEditSafetyPolicy.permitsEdit(
                        nativeDisconnected: disconnected,
                        nativeOnDemandEnabled: onDemand,
                        saveInFlight: busy
                    )
                    let expected = disconnected && !onDemand && !busy
                    precondition(result == expected)
                    if result { allowed += 1 }
                }
            }
        }
        precondition(allowed == 1)
        print("VPN route edits allowed only when disconnected, on-demand off and no save in flight")
    }
}
