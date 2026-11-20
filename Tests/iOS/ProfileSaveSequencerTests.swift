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
}
