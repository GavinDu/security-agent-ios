import Foundation

@main
struct NativePreferenceReloadGateSmoke {
    static func main() {
        var gate = NativePreferenceReloadGate()
        var observed: [String] = []
        let obsolete = gate.begin()
        let newest = gate.begin()
        func deliver(_ token: UInt64, _ name: String, succeeded: Bool = true) {
            let decision = gate.disposition(
                for: token, writeInFlight: false, loadSucceeded: succeeded
            )
            if decision == .publish { observed.append(name) }
        }

        deliver(obsolete, "stale")
        deliver(newest, "latest")
        precondition(observed == ["latest"], "Earlier load overwrote newer profile")

        let beforeNativeSave = gate.begin()
        gate.invalidate() // start native preference save
        precondition(gate.disposition(
            for: beforeNativeSave, writeInFlight: false, loadSucceeded: true
        ) == .discard, "Native save did not invalidate old load")

        let duringLegacySave = gate.begin()
        precondition(gate.disposition(
            for: duringLegacySave, writeInFlight: true, loadSucceeded: true
        ) == .discard, "Legacy on-demand preference write must block load")

        let failure = gate.begin()
        precondition(gate.disposition(
            for: failure, writeInFlight: false, loadSucceeded: false
        ) == .reportFailure, "Failed native load must not publish")
        precondition(gate.disposition(
            for: failure, writeInFlight: false, loadSucceeded: true
        ) == .publish, "Successful current load must be accepted")

        let afterFailure = gate.begin()
        precondition(gate.disposition(
            for: failure, writeInFlight: false, loadSucceeded: false
        ) == .discard, "Obsolete error must not overwrite newer state")
        precondition(gate.disposition(
            for: afterFailure, writeInFlight: false, loadSucceeded: true
        ) == .publish)
        print("Native preference load generations, write invalidation and failures passed")
    }
}
