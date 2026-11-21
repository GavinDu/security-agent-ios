import Foundation

/// Main-queue-confined ordering policy for asynchronous system VPN preference
/// loads. Neither a stale load nor a load overtaken by a native write may
/// replace the last confirmed NETunnelProviderManager.
enum NativePreferenceReloadDisposition: Equatable {
    case discard
    case reportFailure
    case publish
}

struct NativePreferenceReloadGate {
    private var generation: UInt64 = 0

    /// Supersede any earlier load request and capture its unique identity.
    mutating func begin() -> UInt64 {
        invalidate()
        return generation
    }

    /// Must run before a native preference save/on-demand mutation starts.
    mutating func invalidate() {
        generation &+= 1
        if generation == 0 { generation = 1 }
    }

    func disposition(
        for token: UInt64,
        writeInFlight: Bool,
        loadSucceeded: Bool
    ) -> NativePreferenceReloadDisposition {
        guard token != 0, token == generation, !writeInFlight else {
            return .discard
        }
        return loadSucceeded ? .publish : .reportFailure
    }
}
