import Foundation

@main
struct NativePreferenceRollbackSmoke {
    static func main() {
        var captures = 0
        for mask in 0..<128 {
            func flag(_ bit: Int) -> Bool { mask & (1 << bit) != 0 }
            let result = NativePreferenceRollbackPolicy.canCapture(
                priorVerified: flag(0), persistedPrior: flag(1),
                priorSplit: flag(2), attemptedSplit: flag(3),
                priorOnDemand: flag(4), attemptedOnDemand: flag(5),
                differentProfiles: flag(6))
            precondition(result == (mask == 79))
            if result { captures += 1 }
        }
        precondition(captures == 1)
        for mask in 0..<32 {
            func flag(_ bit: Int) -> Bool { mask & (1 << bit) != 0 }
            let result = NativePreferenceRollbackPolicy.decide(
                persistedPrior: flag(0), trustedInventory: flag(1),
                nativeDisconnected: flag(2), nativeMatchesPrior: flag(3),
                nativeMatchesAttempted: flag(4))
            let expected: NativePreferenceRollbackPolicy.Decision =
                !flag(0) || !flag(1) ? .manualRepair :
                flag(3) ? .unchanged :
                flag(2) && flag(4) ? .restore : .manualRepair
            precondition(result == expected)
        }
        print("Native preference rollback: all 160 policy combinations passed")
    }
}
