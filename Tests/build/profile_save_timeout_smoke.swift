import Foundation

private final class ManualPreferenceDeadline {
    final class Entry {
        let seconds: TimeInterval
        let fire: () -> Void
        var cancelled = false

        init(_ seconds: TimeInterval, _ fire: @escaping () -> Void) {
            self.seconds = seconds
            self.fire = fire
        }
    }

    var entries: [Entry] = []

    func schedule(seconds: TimeInterval, fire: @escaping () -> Void) -> () -> Void {
        let entry = Entry(seconds, fire)
        entries.append(entry)
        return { entry.cancelled = true }
    }
}

@main
struct ProfileSaveTimeoutSmoke {
    static func pumpUntil(_ check: () -> Bool) {
        let end = Date().addingTimeInterval(3)
        while !check() && Date() < end {
            _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.01))
        }
        precondition(check(), "Native completion not delivered to main")
    }

    static func main() {
        precondition(Thread.isMainThread)
        let clock = ManualPreferenceDeadline()
        let sequencer = ProfileSaveSequencer(
            scheduleDeadline: { clock.schedule(seconds: $0, fire: $1) }
        )
        var firstSave: ((Error?) -> Void)?
        var oldCompletions = 0
        var oldTimeout = false
        var settled = 0
        var committed = 0
        sequencer.run(
            saveNative: { firstSave = $0 },
            reloadNative: { _ in preconditionFailure("Timed out save reloaded") },
            commitPublicProfile: { committed += 1 },
            nativeSettledAfterTimeout: { settled += 1 },
            completed: { result in
                oldCompletions += 1
                if case .failure(let error) = result,
                   let typed = error as? ProfileSaveSequencer.TransactionError,
                   case .timedOut = typed { oldTimeout = true }
            }
        )
        precondition(sequencer.isBusy && clock.entries.count == 1)
        precondition(clock.entries[0].seconds == 30)
        clock.entries[0].fire()
        precondition(sequencer.isBusy && sequencer.isAwaitingNativeCompletion && oldCompletions == 1 && oldTimeout)
        precondition(clock.entries[0].cancelled && committed == 0)

        // A retry is rejected until the original OS callback settles.
        var rejected = false
        sequencer.run(
            saveNative: { _ in preconditionFailure("Unknown native write still pending") },
            reloadNative: { _ in preconditionFailure("Unexpected reload") },
            commitPublicProfile: { preconditionFailure("Unexpected commit") },
            completed: { result in
                if case .failure(let error) = result,
                   let typed = error as? ProfileSaveSequencer.TransactionError,
                   case .busy = typed { rejected = true }
            }
        )
        precondition(rejected && settled == 0)
        clock.entries[0].fire()
        precondition(oldCompletions == 1)
        firstSave?(nil)
        pumpUntil { settled == 1 }
        precondition(!sequencer.isBusy && committed == 0)
        // Old OS callback and timer cannot hijack the next save.
        var secondSave: ((Error?) -> Void)?
        var secondReload: ((Error?) -> Void)?
        var secondDone = 0
        sequencer.run(
            saveNative: { secondSave = $0 },
            reloadNative: { secondReload = $0 },
            commitPublicProfile: { committed += 1 },
            completed: { result in
                if case .failure = result { preconditionFailure("Fresh transaction failed") }
                secondDone += 1
            }
        )
        precondition(clock.entries.count == 2 && sequencer.isBusy)
        clock.entries[0].fire()  // stale timer after generation advance
        firstSave?(nil)         // stale native completion, stage may be saving
        var drained = false
        DispatchQueue.main.async { drained = true }
        pumpUntil { drained }
        precondition(secondReload == nil && secondDone == 0 && committed == 0)
        secondSave?(nil)
        pumpUntil { secondReload != nil }
        precondition(sequencer.isBusy)
        secondReload?(nil)
        pumpUntil { secondDone == 1 }
        precondition(!sequencer.isBusy && committed == 1)
        precondition(clock.entries[1].cancelled)
        clock.entries[1].fire()  // cancelled timer after success
        precondition(secondDone == 1 && committed == 1 && oldCompletions == 1)

        // Reload callback can also go missing after native save succeeds.
        let clock2 = ManualPreferenceDeadline()
        let reloadStall = ProfileSaveSequencer(
            scheduleDeadline: { clock2.schedule(seconds: $0, fire: $1) }
        )
        var stalledReload: ((Error?) -> Void)?
        var timeoutDone = 0
        var reloadSettled = 0
        reloadStall.run(
            saveNative: { $0(nil) },
            reloadNative: { stalledReload = $0 },
            commitPublicProfile: { preconditionFailure("Reload timed out; public profile committed") },
            nativeSettledAfterTimeout: { reloadSettled += 1 },
            completed: { result in
                guard case .failure(let error) = result,
                      let typed = error as? ProfileSaveSequencer.TransactionError,
                      case .timedOut = typed else {
                    preconditionFailure("Expected distinct reload timeout")
                }
                timeoutDone += 1
            }
        )
        pumpUntil { stalledReload != nil }
        clock2.entries[0].fire()
        precondition(reloadStall.isBusy && reloadStall.isAwaitingNativeCompletion && timeoutDone == 1)
        stalledReload?(nil)
        drained = false
        DispatchQueue.main.async { drained = true }
        pumpUntil { drained }
        precondition(timeoutDone == 1 && clock2.entries[0].cancelled && reloadSettled == 1 && !reloadStall.isBusy)

        let clock3 = ManualPreferenceDeadline()
        let invalidConfig = ProfileSaveSequencer(
            deadlineSeconds: -1,
            scheduleDeadline: { clock3.schedule(seconds: $0, fire: $1) }
        )
        invalidConfig.run(
            saveNative: { _ in },
            reloadNative: { _ in },
            commitPublicProfile: { preconditionFailure("unexpected commit") },
            completed: { _ in }
        )
        precondition(clock3.entries[0].seconds == 30,
                     "Invalid injected deadline may not disable the watchdog")
        clock3.entries[0].fire()
        precondition(invalidConfig.isBusy && invalidConfig.isAwaitingNativeCompletion)

        let syncDeadline = ProfileSaveSequencer(scheduleDeadline: { _, fire in fire(); return {} })
        var syncFailure = 0
        syncDeadline.run(saveNative: { _ in preconditionFailure("Expired before submit") },
                         reloadNative: { _ in preconditionFailure("No reload") },
                         commitPublicProfile: { preconditionFailure("No commit") },
                         completed: { _ in syncFailure += 1 })
        precondition(syncFailure == 1 && !syncDeadline.isBusy)
        print("Native VPN preference timeout, stale epoch, reload failure and cancellation passed")
    }
}
