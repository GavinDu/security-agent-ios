import Foundation

@main
struct BoringTunPendingDrainSmoke {
    enum LocalFailure: Error { case injected }
    static func main() throws {
        for outputs in [0, 1, 2, 256] {
            var calls = 0
            try BoringTunPendingDrainPolicy.drain {
                calls += 1
                return calls <= outputs
            }
            precondition(calls == outputs + 1)
        }
        var calls = 0
        do {
            try BoringTunPendingDrainPolicy.drain { calls += 1; return true }
            fatalError("Unbounded drain accepted")
        } catch BoringTunPendingDrainPolicy.Failure.limitExceeded {
            precondition(calls == 257)
        }
        calls = 0
        do {
            try BoringTunPendingDrainPolicy.drain {
                calls += 1
                throw LocalFailure.injected
            }
            fatalError("Local failure swallowed")
        } catch LocalFailure.injected {
            precondition(calls == 1)
        }
        print("BoringTun queued drain: Done, bounded continuation and error propagation OK")
    }
}
