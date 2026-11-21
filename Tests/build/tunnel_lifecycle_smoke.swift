import Foundation

@main
struct TunnelLifecycleSmoke {
    static func main() {
        var lifetime = TunnelLifecycleGeneration()
        precondition(!lifetime.matches(0))
        let first = lifetime.advance()
        precondition(first != 0 && lifetime.matches(first))
        let oldSettings = first
        let oldReceive = first
        let oldSend = first
        let oldPacketRead = first
        let oldTimer = first
        _ = lifetime.advance() // teardown
        let replacement = lifetime.advance() // new engine
        precondition(lifetime.matches(replacement))
        for stale in [oldSettings, oldReceive, oldSend, oldPacketRead, oldTimer] {
            precondition(!lifetime.matches(stale), "Old async callback was accepted")
        }
        for _ in 0..<4096 {
            let pending = lifetime.current
            lifetime.advance() // teardown + restart simulated by next epoch
            precondition(!lifetime.matches(pending))
            precondition(lifetime.matches(lifetime.current))
        }
        print("BoringTun lifecycle: stale callbacks rejected across 4096 generations")
    }
}
