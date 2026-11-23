import Foundation

@main
struct AgentChatRetryStateSmoke {
    static func main() {
        var state = AgentChatRetryState()
        let first = state.generation
        precondition(!state.isUnavailable)
        precondition(state.reportLoadResult(unreachable: true, generation: first))
        precondition(state.isUnavailable)

        state.retry()
        let second = state.generation
        precondition(second != first)
        precondition(!state.isUnavailable)
        // A late success or failure from the prior page cannot hide a new
        // failure or re-open an old overlay after explicit Retry.
        precondition(!state.reportLoadResult(unreachable: true, generation: first))
        precondition(!state.reportLoadResult(unreachable: false, generation: first))
        precondition(!state.isUnavailable)

        precondition(state.reportLoadResult(unreachable: true, generation: second))
        precondition(state.isUnavailable)
        state.resetForVPNStatusChange()
        let third = state.generation
        precondition(third != second)
        precondition(!state.isUnavailable)
        precondition(!state.reportLoadResult(unreachable: true, generation: second))
        precondition(state.reportLoadResult(unreachable: false, generation: third))
        precondition(!state.isUnavailable)
        precondition(state.reportLoadResult(unreachable: true, generation: third))
        precondition(state.isUnavailable)
        print("Generation-safe VPN-private chat retry policy passed")
    }
}
