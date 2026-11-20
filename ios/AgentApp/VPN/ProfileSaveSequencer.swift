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

    var isBusy: Bool { stage != .idle }

    func run(
        saveNative: NativeStep,
        reloadNative: @escaping NativeStep,
        commitPublicProfile: @escaping () throws -> Void,
        completed: @escaping (Result<Void, Error>) -> Void
    ) {
        precondition(Thread.isMainThread, "VPN profile writes must start on main")
        guard stage == .idle else {
            completed(.failure(TransactionError.busy))
            return
        }
        stage = .saving
        saveNative { [weak self] error in
            DispatchQueue.main.async { [weak self] in
                guard let self, self.stage == .saving else { return }
                if let error {
                    self.finish(.failure(error), completed: completed)
                    return
                }

                self.stage = .loading
                reloadNative { [weak self] error in
                    DispatchQueue.main.async { [weak self] in
                        guard let self, self.stage == .loading else { return }
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
        completed(result)
    }
}
