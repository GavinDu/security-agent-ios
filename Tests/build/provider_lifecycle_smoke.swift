import Foundation

@main
struct ProviderLifecycleSmoke {
    static func main() {
        var state = PacketTunnelProviderState()
        precondition(state.phase == .idle)
        precondition(state.beginStart())
        precondition(!state.beginStart())
        precondition(state.finishStart(success: true))
        precondition(state.phase == .connected)
        precondition(state.beginStop())
        precondition(!state.beginStop())
        precondition(!state.finishStart(success: true))
        precondition(state.finishStop())
        precondition(state.phase == .idle)
        precondition(!state.finishStop())

        precondition(state.beginStart())
        precondition(state.beginStop()) // stop while awaiting Rust handshake
        precondition(!state.finishStart(success: false))
        precondition(state.finishStop())
        precondition(state.beginStart())
        precondition(state.finishStart(success: false)) // failed handshake
        precondition(state.phase == .idle)
        precondition(!state.beginStop())
        for _ in 0..<1024 {
            precondition(state.beginStart())
            precondition(state.finishStart(success: true))
            precondition(state.beginStop())
            precondition(state.finishStop())
        }
        print("Provider lifecycle: serialized start/stop, late callbacks, repeated stop and 1024 cycles passed")
    }
}
