"""Bound both native VPN preferences phases without accepting stale callbacks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "ios/AgentApp/VPN/ProfileSaveSequencer.swift").read_text()
SMOKE = (ROOT / "Tests/build/profile_save_timeout_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/ProfileSaveTimeoutTests.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
APP = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()


class NativeVPNPreferenceDeadlineBoundaryTests(unittest.TestCase):
    def test_deadline_arms_before_any_native_save_and_covers_reload(self):
        run = SOURCE.split("func run(", 1)[1].split("private func finish(", 1)[0]
        self.assertIn("let cancellation = scheduleDeadline(deadlineSeconds)", run)
        self.assertIn("self.transactionEpoch == epoch", run)
        self.assertIn("self.stage != .idle", run)
        self.assertIn("self.finish(.failure(TransactionError.timedOut)", run)
        self.assertLess(run.index("let cancellation = scheduleDeadline("),
                        run.index("saveNative { [weak self]"))
        self.assertNotIn("scheduleDeadline(", run.split("reloadNative { [weak self]", 1)[1])
        self.assertIn("self.stage == .loading", SOURCE)
        self.assertIn("guard self.stage == .saving", SOURCE)
        self.assertIn("self.stage == .awaitingLateSave", SOURCE)
        self.assertIn("self.stage == .awaitingLateReload", SOURCE)
        self.assertIn("if !self.profileSave.isAwaitingNativeCompletion", APP)
        self.assertIn("nativeSettledAfterTimeout:", APP)
        self.assertIn("DispatchQueue.main.async(execute: expire)", run)

    def test_finish_cancels_and_invalidates_before_client_completion(self):
        finish = SOURCE.split("private func finish(", 1)[1]
        self.assertIn("cancelDeadline?()", finish)
        self.assertIn("cancelDeadline = nil", finish)
        self.assertIn("advanceTransactionEpoch()", finish)
        self.assertLess(finish.index("advanceTransactionEpoch()"), finish.index("completed(result)"))
        self.assertIn("case timedOut", SOURCE)
        self.assertIn("deadlineSeconds.isFinite && deadlineSeconds > 0", SOURCE)
        self.assertIn("item.cancel()", SOURCE)
        self.assertIn("Thread.isMainThread", SOURCE)

    def test_running_production_swift_and_native_ios_tests(self):
        self.assertIn("ios/AgentApp/VPN/ProfileSaveSequencer.swift", WORKFLOW)
        self.assertIn("Tests/build/profile_save_timeout_smoke.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("testMissingNativeSaveCallbackTimesOutOnceWithoutPublishing", NATIVE)
        self.assertIn("testNativeReloadMissingCallbackTimesOutBeforeAppGroupCommit", NATIVE)
        self.assertIn("firstSave?(nil)", SMOKE)
        self.assertIn("stalledReload?(nil)", SMOKE)
        # On any save transaction failure, the app reloads actual OS preferences
        # instead of deleting a pre-existing user VPN configuration.
        self.assertIn("self.reload()", APP)


if __name__ == "__main__":
    unittest.main()
