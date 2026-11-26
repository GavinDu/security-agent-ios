import Foundation

/// A single-flight transaction for the public VPN profile. Native system
/// preferences are authoritative: never publish App Group metadata or show
/// success until save *and* reload are acknowledged by NetworkExtension.
///
/// Run is invoked on the main queue. System completion handlers may arrive
/// on background queues; all state changes are serialized onto main.
final class ProfileSaveSequencer {
    typealias NativeStep = (@escaping (Error?) -> Void) -> Void
    typealias DeadlineCancel = () -> Void
    typealias DeadlineScheduler = (TimeInterval, @escaping () -> Void) -> DeadlineCancel
    static let defaultDeadlineSeconds: TimeInterval = 30

    enum TransactionError: LocalizedError {
        case busy
        case timedOut

        var errorDescription: String? {
            switch self {
            case .busy: return "A VPN configuration save is already in progress."
            case .timedOut: return "VPN preferences did not finish updating. Do not reconnect or retry until the native operation completes."
            }
        }
    }

    private enum Stage { case idle, saving, loading, awaitingLateSave, awaitingLateReload }
    private var stage: Stage = .idle
    private var nativeStepSubmitted = false
    // Main-queue-confined identity. A stale native callback must not be
    // accepted when a later transaction happens to be in the same stage.
    private var transactionEpoch: UInt64 = 0
    // Main-queue-confined, per-transaction deadline that covers BOTH native
    // save and reload callbacks. Cancelling it does not cancel an Apple OS
    // preferences write that is already in progress.
    private var cancelDeadline: DeadlineCancel?
    private let deadlineSeconds: TimeInterval
    private let scheduleDeadline: DeadlineScheduler

    init(
        deadlineSeconds: TimeInterval = ProfileSaveSequencer.defaultDeadlineSeconds,
        scheduleDeadline: @escaping DeadlineScheduler = { seconds, handler in
            let item = DispatchWorkItem(block: handler)
            DispatchQueue.main.asyncAfter(deadline: .now() + seconds, execute: item)
            return { item.cancel() }
        }
    ) {
        // An invalid injected timeout may never disable the production gate.
        self.deadlineSeconds = deadlineSeconds.isFinite && deadlineSeconds > 0
            ? deadlineSeconds : Self.defaultDeadlineSeconds
        self.scheduleDeadline = scheduleDeadline
    }

    @discardableResult
    private func advanceTransactionEpoch() -> UInt64 {
        transactionEpoch &+= 1
        if transactionEpoch == 0 { transactionEpoch = 1 }
        return transactionEpoch
    }

    var isBusy: Bool { stage != .idle }
    var isAwaitingNativeCompletion: Bool {
        stage == .awaitingLateSave || stage == .awaitingLateReload
    }

    func run(
        saveNative: @escaping NativeStep,
        reloadNative: @escaping NativeStep,
        commitPublicProfile: @escaping () throws -> Void,
        nativeSettledAfterTimeout: @escaping () -> Void = {},
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
                    nativeSettledAfterTimeout: nativeSettledAfterTimeout,
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
        nativeStepSubmitted = false
        let epoch = advanceTransactionEpoch()
        let cancellation = scheduleDeadline(deadlineSeconds) { [weak self] in
            let expire = { [weak self] in
                guard let self, self.stage != .idle,
                      self.transactionEpoch == epoch else { return }
                guard !self.isAwaitingNativeCompletion else { return }
                // A timeout is a user-visible failure, NOT cancellation of
                // the submitted OS operation. Keep mutation/reload blocked
                // until its terminal callback; never commit a timed-out profile.
                if self.nativeStepSubmitted {
                    self.stage = self.stage == .saving ? .awaitingLateSave : .awaitingLateReload
                    self.cancelDeadline?()
                    self.cancelDeadline = nil
                    completed(.failure(TransactionError.timedOut))
                } else {
                    // A synchronous injected deadline fired before submission.
                    self.finish(.failure(TransactionError.timedOut), completed: completed)
                }
            }
            if Thread.isMainThread {
                expire()
            } else {
                DispatchQueue.main.async(execute: expire)
            }
        }
        // A test scheduler may invoke synchronously. Never initiate native
        // writes if its deadline already invalidated this transaction.
        guard stage == .saving, transactionEpoch == epoch else {
            cancellation()
            return
        }
        cancelDeadline = cancellation
        nativeStepSubmitted = true
        saveNative { [weak self] error in
            DispatchQueue.main.async { [weak self] in
                guard let self, self.transactionEpoch == epoch else { return }
                if self.stage == .awaitingLateSave {
                    self.releaseTimedOutOperation(nativeSettledAfterTimeout)
                    return
                }
                guard self.stage == .saving else { return }
                if let error {
                    self.finish(.failure(error), completed: completed)
                    return
                }

                self.stage = .loading
                reloadNative { [weak self] error in
                    DispatchQueue.main.async { [weak self] in
                        guard let self, self.transactionEpoch == epoch else { return }
                        if self.stage == .awaitingLateReload {
                            self.releaseTimedOutOperation(nativeSettledAfterTimeout)
                            return
                        }
                        guard self.stage == .loading else { return }
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

    private func releaseTimedOutOperation(_ settled: () -> Void) {
        stage = .idle
        nativeStepSubmitted = false
        advanceTransactionEpoch()
        // Reconcile via a fresh native inventory only after the operation
        // settles. Never replay reload/commit or the public completion.
        settled()
    }

    private func finish(
        _ result: Result<Void, Error>,
        completed: (Result<Void, Error>) -> Void
    ) {
        cancelDeadline?()
        cancelDeadline = nil
        stage = .idle
        nativeStepSubmitted = false
        // Invalidate before the client completion, which may immediately
        // start a new transaction on this same sequencer instance.
        advanceTransactionEpoch()
        completed(result)
    }
}
