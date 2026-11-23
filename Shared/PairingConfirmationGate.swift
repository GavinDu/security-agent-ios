/// Binds an explicit fingerprint-confirmation action to the exact public
/// Mac profile that was presented to the user. A Boolean alone cannot prove
/// which QR preview was reviewed if that preview later changes.
///
/// Only public metadata is stored here: never WireGuard private keys/PSKs.
struct PairingConfirmationGate<Profile: Equatable> {
    private(set) var confirmedProfile: Profile?

    mutating func setConfirmed(_ confirmed: Bool, for preview: Profile?) {
        confirmedProfile = confirmed ? preview : nil
    }

    func permitsSave(_ preview: Profile?) -> Bool {
        guard let preview, let confirmedProfile else { return false }
        return confirmedProfile == preview
    }

    mutating func reset() {
        confirmedProfile = nil
    }
}
