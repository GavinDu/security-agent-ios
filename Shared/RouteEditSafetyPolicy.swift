import Foundation

/// Pure app-side safety gate for editing VPN route settings. A stop request
/// is asynchronous: saving route preferences during an active tunnel can
/// race existing packet routes or a system on-demand reconnection.
enum RouteEditSafetyPolicy {
    static func permitsEdit(
        nativeDisconnected: Bool,
        nativeOnDemandEnabled: Bool,
        saveInFlight: Bool
    ) -> Bool {
        nativeDisconnected && !nativeOnDemandEnabled && !saveInFlight
    }
}


/// Main-queue-owned single-flight acknowledgement gate. A notification is
/// not itself proof of disconnect: the caller samples the selected manager.
struct RouteStopTransaction {
    enum Observation: Equatable { case ignored, waiting, commit, cancelled }
    private(set) var token: UUID?
    var isPending: Bool { token != nil }

    mutating func begin() -> UUID? {
        guard token == nil else { return nil }
        let next = UUID()
        token = next
        return next
    }

    mutating func observe(_ observed: UUID, disconnected: Bool,
                          contextValid: Bool) -> Observation {
        guard token == observed else { return .ignored }
        guard contextValid else {
            token = nil
            return .cancelled
        }
        guard disconnected else { return .waiting }
        token = nil
        return .commit
    }

    @discardableResult
    mutating func cancel(_ observed: UUID) -> Bool {
        guard token == observed else { return false }
        token = nil
        return true
    }
}
