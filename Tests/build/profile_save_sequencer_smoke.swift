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
        print("VPN profile success order, overlapping-save rejection and denial recovery passed")
    }
}
