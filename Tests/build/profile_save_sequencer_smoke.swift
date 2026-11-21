import Foundation

@main
struct ProfileSaveSequencerSmoke {
    enum FakeError: Error { case permissionDenied }

    private static func pumpUntil(_ check: () -> Bool) {
        let end = Date().addingTimeInterval(3)
        while !check() && Date() < end {
            _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.01))
        }
        precondition(check(), "Callback did not complete on main")
    }

    static func main() {
        precondition(Thread.isMainThread)
        let sequencer = ProfileSaveSequencer()
        var saveReply: ((Error?) -> Void)?
        var reloadReply: ((Error?) -> Void)?
        var order: [String] = []
        var completed = false
        sequencer.run(
            saveNative: { reply in order.append("save"); saveReply = reply },
            reloadNative: { reply in order.append("reload"); reloadReply = reply },
            commitPublicProfile: { order.append("commit") },
            completed: { result in
                if case .failure = result { preconditionFailure("Unexpected failure") }
                order.append("complete")
                completed = true
            }
        )
        precondition(sequencer.isBusy && order == ["save"])
        var busyRejected = false
        sequencer.run(
            saveNative: { _ in preconditionFailure("Second native save started") },
            reloadNative: { _ in preconditionFailure("Second native reload started") },
            commitPublicProfile: { preconditionFailure("Second commit started") },
            completed: { result in
                if case .failure(let error) = result,
                   let transaction = error as? ProfileSaveSequencer.TransactionError,
                   case .busy = transaction { busyRejected = true }
            }
        )
        precondition(busyRejected)
        saveReply?(nil)
        pumpUntil { reloadReply != nil }
        precondition(order == ["save", "reload"])
        reloadReply?(nil)
        pumpUntil { completed }
        precondition(order == ["save", "reload", "commit", "complete"])
        precondition(!sequencer.isBusy)

        completed = false
        var denied: ((Error?) -> Void)?
        sequencer.run(
            saveNative: { denied = $0 },
            reloadNative: { _ in preconditionFailure("Reload after denial") },
            commitPublicProfile: { preconditionFailure("Publish after denial") },
            completed: { result in
                if case .success = result { preconditionFailure("Denial became success") }
                completed = true
            }
        )
        denied?(FakeError.permissionDenied)
        pumpUntil { completed }
        precondition(!sequencer.isBusy)
        // Replay a failed transaction's save callback after a newer
        // transaction starts. Stage-only guards would incorrectly accept it.
        let first = ProfileSaveSequencer()
        var oldSave: ((Error?) -> Void)?
        var newSave: ((Error?) -> Void)?
        var newReload: ((Error?) -> Void)?
        var oldCompleted = 0
        var newCompleted = 0
        var committed: [String] = []
        first.run(
            saveNative: { oldSave = $0 },
            reloadNative: { _ in preconditionFailure("denied old save reloaded") },
            commitPublicProfile: { preconditionFailure("denied old save committed") },
            completed: { _ in oldCompleted += 1 }
        )
        oldSave?(FakeError.permissionDenied)
        pumpUntil { oldCompleted == 1 }
        first.run(
            saveNative: { newSave = $0 },
            reloadNative: { newReload = $0 },
            commitPublicProfile: { committed.append("new") },
            completed: { result in
                if case .failure = result { preconditionFailure("new save failed") }
                newCompleted += 1
            }
        )
        oldSave?(nil) // must not invoke stale reload/commit
        var drained = false
        DispatchQueue.main.async { drained = true }
        pumpUntil { drained }
        precondition(first.isBusy && newReload == nil && oldCompleted == 1)
        newSave?(nil)
        pumpUntil { newReload != nil }
        newReload?(nil)
        pumpUntil { newCompleted == 1 }
        precondition(committed == ["new"] && oldCompleted == 1 && !first.isBusy)

        // Replay a previously successful reload while next save is loading.
        let second = ProfileSaveSequencer()
        var firstReload: ((Error?) -> Void)?
        var secondSave: ((Error?) -> Void)?
        var secondReload: ((Error?) -> Void)?
        var completions = 0
        var publications: [String] = []
        second.run(
            saveNative: { $0(nil) },
            reloadNative: { firstReload = $0 },
            commitPublicProfile: { publications.append("first") },
            completed: { _ in completions += 1 }
        )
        pumpUntil { firstReload != nil }
        firstReload?(nil)
        pumpUntil { completions == 1 }
        second.run(
            saveNative: { secondSave = $0 },
            reloadNative: { secondReload = $0 },
            commitPublicProfile: { publications.append("second") },
            completed: { _ in completions += 1 }
        )
        secondSave?(nil)
        pumpUntil { secondReload != nil }
        firstReload?(nil)
        drained = false
        DispatchQueue.main.async { drained = true }
        pumpUntil { drained }
        precondition(publications == ["first"] && second.isBusy && completions == 1)
        secondReload?(nil)
        pumpUntil { completions == 2 }
        precondition(publications == ["first", "second"] && !second.isBusy)

        print("VPN staged save ordering, denial, busy guard and stale/duplicate native callbacks passed")
    }
}
