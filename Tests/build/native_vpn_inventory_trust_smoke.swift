import Foundation

@main
struct NativeVPNInventoryTrustSmoke {
    static func main() {
        var trust = NativeVPNInventoryTrust()
        precondition(!trust.permitsMutation)
        precondition(trust.state == .unverified)

        trust.beginLoad()
        precondition(trust.state == .loading && !trust.permitsMutation)
        trust.didFailLoad() // permission denied / nil managers / unexpected error
        precondition(trust.state == .failed && !trust.permitsMutation)
        trust.didCommitVerifiedWrite() // cannot bless a failed native read
        precondition(!trust.permitsMutation)

        trust.beginLoad()
        trust.didLoadUniqueInventory()
        precondition(trust.permitsMutation)
        trust.beginLoad()
        trust.didFailLoad() // formerly valid reference is now stale
        precondition(trust.state == .failed && !trust.permitsMutation)

        trust.beginLoad()
        trust.didLoadDuplicateInventory()
        precondition(trust.state == .ambiguous && !trust.permitsMutation)
        trust.didLoadUniqueInventory() // an obsolete callback cannot clear ambiguity
        precondition(!trust.permitsMutation)

        trust.beginLoad()
        trust.didLoadUniqueInventory() // current successful reconciliation
        precondition(trust.permitsMutation)
        trust.beginWrite()
        precondition(trust.state == .unverified && !trust.permitsMutation)
        trust.didFailLoad() // old completion after invalidation ignored
        precondition(trust.state == .unverified)
        trust.didCommitVerifiedWrite() // only after verified native save+reload+commit
        precondition(trust.permitsMutation)

        trust.beginWrite()
        precondition(!trust.permitsMutation)
        trust.beginLoad() // native save/legacy on-demand write failed; recover via read
        trust.didLoadUniqueInventory()
        precondition(trust.permitsMutation)

        // Rejected stale callback must not mutate the current inventory trust.
        var gate = NativePreferenceReloadGate()
        let obsolete = gate.begin()
        trust.beginLoad()
        let newest = gate.begin()
        trust.beginLoad()
        precondition(gate.disposition(
            for: obsolete, writeInFlight: false, loadSucceeded: false
        ) == .discard)
        precondition(trust.state == .loading && !trust.permitsMutation)
        precondition(gate.disposition(
            for: newest, writeInFlight: false, loadSucceeded: true
        ) == .publish)
        trust.didLoadUniqueInventory()
        precondition(trust.permitsMutation)
        print("Native inventory trust: denial, stale results, ambiguity and verified recovery passed")
    }
}
