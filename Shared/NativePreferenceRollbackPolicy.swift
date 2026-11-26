import Foundation

/// Conservative in-process compensation policy. A failed callback alone
/// is not evidence that native preferences changed (or did not change).
enum NativePreferenceRollbackPolicy {
    enum Decision: Equatable { case unchanged, restore, manualRepair }

    static func canCapture(priorVerified: Bool, persistedPrior: Bool,
                           priorSplit: Bool, attemptedSplit: Bool,
                           priorOnDemand: Bool, attemptedOnDemand: Bool,
                           differentProfiles: Bool) -> Bool {
        priorVerified && persistedPrior && priorSplit && attemptedSplit &&
            !priorOnDemand && !attemptedOnDemand && differentProfiles
    }

    static func decide(persistedPrior: Bool, trustedInventory: Bool,
                       nativeDisconnected: Bool, nativeMatchesPrior: Bool,
                       nativeMatchesAttempted: Bool) -> Decision {
        guard persistedPrior, trustedInventory else { return .manualRepair }
        if nativeMatchesPrior { return .unchanged }
        guard nativeDisconnected, nativeMatchesAttempted else { return .manualRepair }
        return .restore
    }
}
