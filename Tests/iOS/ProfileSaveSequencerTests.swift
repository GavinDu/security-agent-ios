import Foundation
import XCTest
@testable import AgentApp

final class ProfileSaveSequencerTests: XCTestCase {
    private enum FakeError: Error {
        case denied
        case reloadFailed
        case storeFailed
    }

    func testPublishingOccursOnlyAfterNativeSaveAndReload() {
        let sequencer = ProfileSaveSequencer()
        var events: [String] = []
        var saveReply: ((Error?) -> Void)?
        var reloadReply: ((Error?) -> Void)?
        let reloadStarted = expectation(description: "system preferences reloaded")
        let completed = expectation(description: "public profile published")

        sequencer.run(
            saveNative: { reply in
                events.append("native-save")
                saveReply = reply
            },
            reloadNative: { reply in
                events.append("native-reload")
                reloadReply = reply
                reloadStarted.fulfill()
            },
            commitPublicProfile: {
                events.append("public-commit")
            },
            completed: { result in
                guard case .success = result else {
                    XCTFail("Expected a successful preference transaction")
                    completed.fulfill()
                    return
                }
                events.append("success")
                completed.fulfill()
            }
        )
        XCTAssertTrue(sequencer.isBusy)
        XCTAssertEqual(events, ["native-save"])
        saveReply?(nil)
        wait(for: [reloadStarted], timeout: 3)
        XCTAssertEqual(events, ["native-save", "native-reload"])
        XCTAssertTrue(sequencer.isBusy)
        reloadReply?(nil)
        wait(for: [completed], timeout: 3)
        XCTAssertFalse(sequencer.isBusy)
        XCTAssertEqual(events, ["native-save", "native-reload", "public-commit", "success"])
    }

    func testDeniedNativeSaveNeverReloadsOrPublishes() {
        let sequencer = ProfileSaveSequencer()
        var saveReply: ((Error?) -> Void)?
        let completed = expectation(description: "denied profile save")
        sequencer.run(
            saveNative: { saveReply = $0 },
            reloadNative: { _ in XCTFail("Must not reload after denied save") },
            commitPublicProfile: {
                XCTFail("Must not publish denied profile")
            },
            completed: { result in
                guard case .failure = result else { XCTFail("Expected denial"); return }
                completed.fulfill()
            }
        )
        saveReply?(FakeError.denied)
        wait(for: [completed], timeout: 3)
        XCTAssertFalse(sequencer.isBusy)
    }

    func testReloadErrorDoesNotPublishAndReleasesSingleFlight() {
        let sequencer = ProfileSaveSequencer()
        var saveReply: ((Error?) -> Void)?
        let reloadStarted = expectation(description: "native reload")
        let completed = expectation(description: "reload failure")
        sequencer.run(
            saveNative: { saveReply = $0 },
            reloadNative: { reply in
                reloadStarted.fulfill()
                reply(FakeError.reloadFailed)
            },
            commitPublicProfile: { XCTFail("Must not commit after reload error") },
            completed: { result in
                guard case .failure = result else { XCTFail("Expected reload failure"); return }
                completed.fulfill()
            }
        )
        saveReply?(nil)
        wait(for: [reloadStarted, completed], timeout: 3)
        XCTAssertFalse(sequencer.isBusy)
    }

    func testSharedStoreErrorLeavesFailureAndAllowsRetry() {
        let sequencer = ProfileSaveSequencer()
        var count = 0
        let completed = expectation(description: "shared store error")
        sequencer.run(
            saveNative: { $0(nil) },
            reloadNative: { $0(nil) },
            commitPublicProfile: {
                count += 1
                throw FakeError.storeFailed
            },
            completed: { result in
                guard case .failure = result else { XCTFail("Expected storage error"); return }
                completed.fulfill()
            }
        )
        wait(for: [completed], timeout: 3)
        XCTAssertEqual(count, 1)
        XCTAssertFalse(sequencer.isBusy)

        let retry = expectation(description: "subsequent save succeeds")
        sequencer.run(
            saveNative: { $0(nil) },
            reloadNative: { $0(nil) },
            commitPublicProfile: { count += 1 },
            completed: { result in
                if case .failure = result { XCTFail("Retry failed") }
                retry.fulfill()
            }
        )
        wait(for: [retry], timeout: 3)
        XCTAssertEqual(count, 2)
    }

    func testBackgroundCallerRunsTransactionOnMainWithoutCrashing() {
        let sequencer = ProfileSaveSequencer()
        let completed = expectation(description: "background request completed")
        DispatchQueue.global(qos: .userInitiated).async {
            sequencer.run(
                saveNative: { reply in
                    XCTAssertTrue(Thread.isMainThread)
                    reply(nil)
                },
                reloadNative: { reply in
                    XCTAssertTrue(Thread.isMainThread)
                    reply(nil)
                },
                commitPublicProfile: {
                    XCTAssertTrue(Thread.isMainThread)
                },
                completed: { result in
                    XCTAssertTrue(Thread.isMainThread)
                    if case .failure = result { XCTFail("Background request failed") }
                    completed.fulfill()
                }
            )
        }
        wait(for: [completed], timeout: 3)
    }
    func testConcurrentSaveIsRejectedWithoutStartingItsNativeWork() {
        let sequencer = ProfileSaveSequencer()
        var firstReply: ((Error?) -> Void)?
        let finished = expectation(description: "first save denied")
        sequencer.run(
            saveNative: { firstReply = $0 },
            reloadNative: { _ in XCTFail("Denied save must not reload") },
            commitPublicProfile: { XCTFail("Denied save must not publish") },
            completed: { _ in finished.fulfill() }
        )
        var sawBusy = false
        sequencer.run(
            saveNative: { _ in XCTFail("Second native save must not start") },
            reloadNative: { _ in XCTFail("Second native reload must not start") },
            commitPublicProfile: { XCTFail("Second profile must not publish") },
            completed: { result in
                if case .failure(let error) = result,
                   let transaction = error as? ProfileSaveSequencer.TransactionError,
                   case .busy = transaction {
                    sawBusy = true
                }
            }
        )
        XCTAssertTrue(sawBusy)
        XCTAssertTrue(sequencer.isBusy)
        firstReply?(FakeError.denied)
        wait(for: [finished], timeout: 3)
        XCTAssertFalse(sequencer.isBusy)
    }
    func testLateSaveCallbackCannotHijackLaterSavingTransaction() {
        let sequencer = ProfileSaveSequencer()
        var oldSave: ((Error?) -> Void)?
        var newSave: ((Error?) -> Void)?
        var newReload: ((Error?) -> Void)?
        var completedOld = 0
        var completedNew = 0
        var commits = 0
        let failedOld = expectation(description: "old denied save")
        let reloadedNew = expectation(description: "new transaction reload")
        let succeededNew = expectation(description: "new transaction completed")

        sequencer.run(
            saveNative: { oldSave = $0 },
            reloadNative: { _ in XCTFail("old denied save cannot reload") },
            commitPublicProfile: { XCTFail("old denied save cannot commit") },
            completed: { result in
                if case .success = result { XCTFail("old save must fail") }
                completedOld += 1
                failedOld.fulfill()
            }
        )
        oldSave?(FakeError.denied)
        wait(for: [failedOld], timeout: 3)

        sequencer.run(
            saveNative: { newSave = $0 },
            reloadNative: { newReload = $0; reloadedNew.fulfill() },
            commitPublicProfile: { commits += 1 },
            completed: { result in
                if case .failure = result { XCTFail("new save unexpectedly failed") }
                completedNew += 1
                succeededNew.fulfill()
            }
        )
        XCTAssertTrue(sequencer.isBusy)
        oldSave?(nil) // replay from earlier transaction while phase is saving
        let drained = expectation(description: "late old save callback drained")
        DispatchQueue.main.async { drained.fulfill() }
        wait(for: [drained], timeout: 3)
        XCTAssertNil(newReload)
        XCTAssertEqual(completedOld, 1)
        XCTAssertTrue(sequencer.isBusy)

        newSave?(nil)
        wait(for: [reloadedNew], timeout: 3)
        newReload?(nil)
        wait(for: [succeededNew], timeout: 3)
        XCTAssertEqual(commits, 1)
        XCTAssertEqual(completedOld, 1)
        XCTAssertEqual(completedNew, 1)
        XCTAssertFalse(sequencer.isBusy)
    }

    func testLateReloadCannotCommitOldProfileDuringLaterLoadingTransaction() {
        let sequencer = ProfileSaveSequencer()
        var oldReload: ((Error?) -> Void)?
        var newSave: ((Error?) -> Void)?
        var newReload: ((Error?) -> Void)?
        var committed: [String] = []
        var oldCompletions = 0
        var newCompletions = 0
        let oldDone = expectation(description: "first transaction completed")
        let newReloadStarted = expectation(description: "second reload started")
        let newDone = expectation(description: "second transaction completed")

        sequencer.run(
            saveNative: { $0(nil) },
            reloadNative: { oldReload = $0 },
            commitPublicProfile: { committed.append("first") },
            completed: { result in
                if case .failure = result { XCTFail("first transaction failed") }
                oldCompletions += 1
                oldDone.fulfill()
            }
        )
        // Save callback dispatches through main, so wait for reload capture.
        let oldReloadReady = expectation(description: "first reload captured")
        DispatchQueue.main.async { oldReloadReady.fulfill() }
        wait(for: [oldReloadReady], timeout: 3)
        XCTAssertNotNil(oldReload)
        oldReload?(nil)
        wait(for: [oldDone], timeout: 3)

        sequencer.run(
            saveNative: { newSave = $0 },
            reloadNative: { newReload = $0; newReloadStarted.fulfill() },
            commitPublicProfile: { committed.append("second") },
            completed: { result in
                if case .failure = result { XCTFail("second transaction failed") }
                newCompletions += 1
                newDone.fulfill()
            }
        )
        newSave?(nil)
        wait(for: [newReloadStarted], timeout: 3)
        oldReload?(nil) // replay from earlier transaction while phase is loading
        let drained = expectation(description: "late old reload callback drained")
        DispatchQueue.main.async { drained.fulfill() }
        wait(for: [drained], timeout: 3)
        XCTAssertTrue(sequencer.isBusy)
        XCTAssertEqual(committed, ["first"])
        XCTAssertEqual(oldCompletions, 1)

        newReload?(nil)
        wait(for: [newDone], timeout: 3)
        XCTAssertEqual(committed, ["first", "second"])
        XCTAssertEqual(oldCompletions, 1)
        XCTAssertEqual(newCompletions, 1)
        XCTAssertFalse(sequencer.isBusy)
    }

}
