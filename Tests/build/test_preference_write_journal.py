"""Enforce journal before native write and no automatic relaunch recovery."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
APP = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
EXT = (ROOT / "ios/PacketTunnel/PacketTunnelProvider.swift").read_text()
class PreferenceJournalBoundaryTests(unittest.TestCase):
    def test_both_native_writes_arm_marker_before_mutating(self):
        save = APP.split("func save(_ candidate:", 1)[1].split("func connect()", 1)[0]
        legacy = APP.split("private func remediateLegacyFullTunnel()", 1)[1].split("func save(_ candidate:", 1)[0]
        self.assertLess(save.index("preferenceJournal.begin()"), save.index("nativeInventoryTrust.beginWrite()"))
        self.assertLess(legacy.index("preferenceJournal.begin()"), legacy.index("manager.isOnDemandEnabled = false"))
        self.assertIn("if !self.profileSave.isAwaitingNativeCompletion", save)
        self.assertIn("finishPreferenceJournal(journalToken)", save)
        self.assertLess(EXT.index("SharedPreferenceWriteJournal.current.state == .clear"), EXT.index("let transport = BoringTunTransport"))
    def test_relaunch_only_clears_after_explicit_request_and_empty_inventory(self):
        recovery = APP.split("private func finishManualPreferenceRecovery", 1)[1].split("private func finishPreferenceJournal", 1)[0]
        self.assertIn("nativeInventoryTrust.permitsMutation && manager == nil", recovery)
        self.assertIn("ownerConfirmedRestartAndRemoval: true", recovery)
        self.assertNotIn("startVPNTunnel", recovery)
        self.assertNotIn("removeFromPreferences", recovery)
        self.assertIn("requestedManualRecovery = nil", APP)
        self.assertIn("if let manualRecovery", APP)
if __name__ == "__main__":
    unittest.main()
