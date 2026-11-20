"""Reject replayed native preference callbacks across VPN save epochs."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class ProfileSaveEpochTests(unittest.TestCase):
    def test_both_native_callbacks_verify_transaction_identity(self):
        src = (ROOT / "ios/AgentApp/VPN/ProfileSaveSequencer.swift").read_text()
        self.assertIn("private var transactionEpoch: UInt64", src)
        self.assertIn("let epoch = advanceTransactionEpoch()", src)
        self.assertEqual(src.count("self.transactionEpoch == epoch"), 2)
        self.assertIn("guard let self, self.stage == .saving,", src)
        self.assertIn("guard let self, self.stage == .loading,", src)
        # Completion is reentrant; invalidate before caller starts next save.
        finish = src[src.index("private func finish("):]
        self.assertLess(finish.index("advanceTransactionEpoch()"), finish.index("completed(result)"))

    def test_real_swift_and_native_tests_replay_delayed_callbacks(self):
        smoke = (ROOT / "Tests/build/profile_save_sequencer_smoke.swift").read_text()
        native = (ROOT / "Tests/iOS/ProfileSaveSequencerTests.swift").read_text()
        self.assertIn("oldSave?(nil)", smoke)
        self.assertIn("firstReload?(nil)", smoke)
        self.assertIn("testLateSaveCallbackCannotHijackLaterSavingTransaction", native)
        self.assertIn("testLateReloadCannotCommitOldProfileDuringLaterLoadingTransaction", native)

if __name__ == "__main__":
    unittest.main()
