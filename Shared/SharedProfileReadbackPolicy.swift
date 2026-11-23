import Foundation

/// Immediate public App Group profile save/readback consistency check.
/// UserDefaults returns no write error; matching its cached readback does
/// NOT promise that bytes are durably synced across crashes or processes.
/// Native VPN preferences remain an independent store, verified separately.
enum SharedProfileReadbackPolicy {
    static func accepts(expected: Data, observed: Data?) -> Bool {
        guard SharedProfileDataPolicy.accepts(expected),
              let observed,
              SharedProfileDataPolicy.accepts(observed) else {
            return false
        }
        return observed == expected
    }
}
