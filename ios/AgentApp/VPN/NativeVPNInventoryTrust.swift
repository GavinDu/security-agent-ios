import Foundation

/// Main-queue-confined trust in the last completed native VPN preference
/// inventory. In particular, a failed load is never equivalent to an empty
/// inventory: guessing would allow duplicate or stale native VPN writes.
struct NativeVPNInventoryTrust {
    enum State: Equatable {
        case unverified
        case loading
        case verified
        case failed
        case ambiguous
    }

    private(set) var state: State = .unverified

    var permitsMutation: Bool { state == .verified }

    mutating func beginLoad() {
        state = .loading
    }

    mutating func didLoadUniqueInventory() {
        guard state == .loading else { return }
        state = .verified
    }

    mutating func didLoadDuplicateInventory() {
        guard state == .loading else { return }
        state = .ambiguous
    }

    mutating func didFailLoad() {
        guard state == .loading else { return }
        state = .failed
    }

    /// A native preference mutation makes the previous system inventory
    /// untrustworthy until it has been reloaded/verified or replaced by a
    /// successful, fully verified save+App Group commit.
    mutating func beginWrite() {
        state = .unverified
    }

    mutating func didCommitVerifiedWrite() {
        guard state == .unverified else { return }
        state = .verified
    }
}
