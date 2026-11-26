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
        var gate = RouteStopTransaction()
        let first = gate.begin()!
        precondition(gate.begin() == nil)
        precondition(gate.observe(first, disconnected: false, contextValid: true) == .waiting)
        precondition(gate.cancel(first))
        let second = gate.begin()!
        precondition(first != second)
        precondition(!gate.cancel(first))
        precondition(gate.observe(first, disconnected: true, contextValid: true) == .ignored)
        precondition(gate.observe(second, disconnected: true, contextValid: false) == .cancelled)
        let third = gate.begin()!
        precondition(gate.observe(third, disconnected: true, contextValid: true) == .commit)
        precondition(gate.observe(third, disconnected: true, contextValid: true) == .ignored)
        precondition(!gate.isPending)
        print("VPN route edits allowed only when disconnected, on-demand off and no save in flight")
    }
}
