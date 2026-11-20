import Foundation

/// A single-flight transaction for the public VPN profile. Native system
/// preferences are authoritative: never publish App Group metadata or show
/// success until save *and* reload are acknowledged by NetworkExtension.
///
/// Run is invoked on the main queue. System completion handlers may arrive
/// on background queues; all state changes are serialized onto main.
final class ProfileSaveSequencer {
    typealias NativeStep = (@escaping (Error?) -> Void) -> Void

    enum TransactionError: LocalizedError {
        case busy

        var errorDescription: String? {
            switch self {
            case .busy: return "A VPN configuration save is already in progress."
            }
        }
    }

    private enum Stage { case idle, saving, loading }
    private var stage: Stage = .idle
    // Main-queue-confined identity. A stale native callback must not be
    // accepted when a later transaction happens to be in the same stage.
    private var transactionEpoch: UInt64 = 0

    @discardableResult
    private func advanceTransactionEpoch() -> UInt64 {
        transactionEpoch &+= 1
        if transactionEpoch == 0 { transactionEpoch = 1 }
        return transactionEpoch
    }

    var isBusy: Bool { stage != .idle }

    func run(
        saveNative: @escaping NativeStep,
        reloadNative: @escaping NativeStep,
        commitPublicProfile: @escaping () throws -> Void,
        completed: @escaping (Result<Void, Error>) -> Void
    ) {
        // UI normally calls on main, but an unexpected background caller
        // must not crash the app. Marshal the entire transaction instead.
        if !Thread.isMainThread {
            DispatchQueue.main.async {
                self.run(
                    saveNative: saveNative,
                    reloadNative: reloadNative,
                    commitPublicProfile: commitPublicProfile,
                    completed: completed
                )
            }
            return
        }
        guard stage == .idle else {
            completed(.failure(TransactionError.busy))
            return
        }
        stage = .saving
        let epoch = advanceTransactionEpoch()
        saveNative { [weak self] error in
            DispatchQueue.main.async { [weak self] in
                guard let self, self.stage == .saving,
                      self.transactionEpoch == epoch else { return }
                if let error {
                    self.finish(.failure(error), completed: completed)
                    return
                }

                self.stage = .loading
                reloadNative { [weak self] error in
                    DispatchQueue.main.async { [weak self] in
                        guard let self, self.stage == .loading,
                              self.transactionEpoch == epoch else { return }
                        if let error {
                            self.finish(.failure(error), completed: completed)
                            return
                        }
                        do {
                            try commitPublicProfile()
                            self.finish(.success(()), completed: completed)
                        } catch {
                            self.finish(.failure(error), completed: completed)
                        }
                    }
                }
            }
        }
    }

    private func finish(
        _ result: Result<Void, Error>,
        completed: (Result<Void, Error>) -> Void
    ) {
        stage = .idle
        // Invalidate before the client completion, which may immediately
        // start a new transaction on this same sequencer instance.
        advanceTransactionEpoch()
        completed(result)
    }
}
