import Foundation
import XCTest
@testable import AgentApp

private final class TestPreferenceDeadline {
    var event: (() -> Void)?
    var cancelled = false
    func schedule(_ seconds: TimeInterval, _ work: @escaping () -> Void) -> () -> Void {
        event = work
        XCTAssertEqual(seconds, 30)
        return { self.cancelled = true }
    }
}

final class ProfileSaveTimeoutTests: XCTestCase {
    func testMissingNativeSaveCallbackTimesOutOnceWithoutPublishing() {
        let manual = TestPreferenceDeadline()
        let sequencer = ProfileSaveSequencer(
            scheduleDeadline: { manual.schedule($0, $1) }
        )
        var nativeSave: ((Error?) -> Void)?
        var completions = 0
        let timedOut = expectation(description: "native save timed out")
        sequencer.run(
            saveNative: { nativeSave = $0 },
            reloadNative: { _ in XCTFail("Timed-out save must not reload") },
            commitPublicProfile: { XCTFail("Timed-out save must not publish") },
            completed: { result in
                guard case .failure(let error) = result,
                      let typed = error as? ProfileSaveSequencer.TransactionError,
                      case .timedOut = typed else {
                    XCTFail("Expected a native preference timeout")
                    return
                }
                completions += 1
                timedOut.fulfill()
            }
        )
        XCTAssertTrue(sequencer.isBusy)
        manual.event?()
        wait(for: [timedOut], timeout: 3)
        XCTAssertFalse(sequencer.isBusy)
        XCTAssertEqual(completions, 1)
        XCTAssertTrue(manual.cancelled)
        nativeSave?(nil)
        let drained = expectation(description: "stale native save discarded")
        DispatchQueue.main.async { drained.fulfill() }
        wait(for: [drained], timeout: 3)
        XCTAssertEqual(completions, 1)
    }

    func testNativeReloadMissingCallbackTimesOutBeforeAppGroupCommit() {
        let manual = TestPreferenceDeadline()
        let sequencer = ProfileSaveSequencer(
            scheduleDeadline: { manual.schedule($0, $1) }
        )
        let reloading = expectation(description: "native reload started")
        var reload: ((Error?) -> Void)?
        var completions = 0
        let timedOut = expectation(description: "native reload timed out")
        sequencer.run(
            saveNative: { $0(nil) },
            reloadNative: { reload = $0; reloading.fulfill() },
            commitPublicProfile: { XCTFail("Timed-out reload must not publish") },
            completed: { result in
                if case .failure(let error) = result,
                   let typed = error as? ProfileSaveSequencer.TransactionError,
                   case .timedOut = typed {
                    completions += 1
                    timedOut.fulfill()
                }
            }
        )
        wait(for: [reloading], timeout: 3)
        manual.event?()
        wait(for: [timedOut], timeout: 3)
        XCTAssertFalse(sequencer.isBusy)
        XCTAssertTrue(manual.cancelled)
        reload?(nil)
        let drained = expectation(description: "stale reload discarded")
        DispatchQueue.main.async { drained.fulfill() }
        wait(for: [drained], timeout: 3)
        XCTAssertEqual(completions, 1)
    }
}
