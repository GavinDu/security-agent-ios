"""Source-level integration guards for native preference reload callback ordering."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
GATE = (ROOT / "ios/AgentApp/VPN/NativePreferenceReloadGate.swift").read_text()


class NativePreferenceReloadBoundaryTests(unittest.TestCase):
    def test_reload_uses_single_main_queue_generation_and_result_gate(self):
        section = SOURCE.split("    func reload() {", 1)[1].split(
            "    /// Stop any inherited full-tunnel session", 1
        )[0]
        self.assertIn("DispatchQueue.main.async", section)
        self.assertIn("let loadToken = preferenceReloadGate.begin()", section)
        self.assertIn("preferenceReloadGate.disposition(", section)
        self.assertIn("loadSucceeded: error == nil && managers != nil", section)
        # After #81, the callback generation guard must precede a
        # unique/duplicate inventory decision; arbitrary first-match
        # publication is intentionally forbidden.
        self.assertLess(section.index("preferenceReloadGate.disposition("),
                        section.index("NativeVPNManagerInventory.select("))
        self.assertLess(section.index("NativeVPNManagerInventory.select("),
                        section.index("self.manager = selected"))
        self.assertIn("case .duplicate:", section)
        self.assertNotIn("self.manager = managers?", section)
        self.assertIn("case .reportFailure:", section)
        self.assertIn("case .discard:", section)
        self.assertIn("return", section)
        self.assertIn("guard !profileSave.isBusy && !legacyOnDemandDisableInFlight", section)

    def test_native_writes_invalidate_pending_reload_before_mutation(self):
        saving = SOURCE.split("    func save(_ candidate:", 1)[1].split(
            "    func connect()", 1
        )[0]
        self.assertIn("if !Thread.isMainThread", saving)
        self.assertLess(saving.index("if !Thread.isMainThread"),
                        saving.index("preferenceReloadGate.invalidate()"))
        self.assertLess(saving.index("preferenceReloadGate.invalidate()"),
                        saving.index("selected.saveToPreferences"))
        legacy = SOURCE.split("    private func remediateLegacyFullTunnel()", 1)[1].split(
            "    func save(_ candidate:", 1
        )[0]
        self.assertLess(legacy.index("preferenceReloadGate.invalidate()"),
                        legacy.index("manager.saveToPreferences"))

    def test_gate_rejects_stale_and_inflight_callbacks(self):
        self.assertIn("token == generation", GATE)
        self.assertIn("!writeInFlight", GATE)
        self.assertIn("case discard", GATE)
        self.assertIn("case reportFailure", GATE)
        self.assertIn("case publish", GATE)


if __name__ == "__main__":
    unittest.main()
