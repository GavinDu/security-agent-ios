import Foundation

@main
struct WireGuardStartupWatchdogSmoke {
    static func main() {
        let check = WireGuardStartupWatchdogPolicy.shouldExpire
        precondition(WireGuardStartupWatchdogPolicy.timeoutSeconds == 30)
        precondition(check(true, true, 1, 1), "Pending current startup must expire")
        precondition(!check(false, true, 1, 1), "Stopped tunnel cannot expire")
        precondition(!check(true, false, 1, 1), "Completed startup cannot expire")
        precondition(!check(true, true, 0, 0), "Uninitialized session cannot expire")
        precondition(!check(true, true, 1, 2), "Old timer cannot stop next tunnel")
        precondition(!check(true, true, 2, 1), "Future token cannot expire current tunnel")
        precondition(check(true, true, UInt64.max, UInt64.max))
        print("Rust PacketTunnel overall startup watchdog conditions passed")
    }
}
