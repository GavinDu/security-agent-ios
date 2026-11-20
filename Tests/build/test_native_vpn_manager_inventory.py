"""Guard native VPN inventory consistency and first-load save ordering."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MANAGER = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
SELECTOR = (ROOT / "ios/AgentApp/VPN/NativeVPNManagerInventory.swift").read_text()


class NativeVPNManagerInventoryBoundaryTests(unittest.TestCase):
    def test_reload_rejects_duplicate_instead_of_first_match(self):
        body = MANAGER.split("func reload() {", 1)[1].split(
            "/// Stop any inherited full-tunnel session", 1
        )[0]
        self.assertIn("nativeInventoryLoading = true", body)
        self.assertIn("NativeVPNManagerInventory.select(", body)
        self.assertIn("case .duplicate:", body)
        self.assertIn("self.duplicateNativeManagers = true", body)
        self.assertIn("self.manager = nil", body)
        self.assertNotIn(".first(where:", body)
        self.assertLess(body.index("self.preferenceReloadGate.disposition("),
                        body.index("NativeVPNManagerInventory.select("))
        self.assertIn("case .reportFailure:", body)
        self.assertIn("self.nativeInventoryLoading = false", body)

    def test_save_and_connect_are_blocked_on_loading_or_ambiguity(self):
        save = MANAGER.split("func save(_ candidate:", 1)[1].split(
            "func connect()", 1
        )[0]
        connect = MANAGER.split("func connect()", 1)[1].split(
            "func disconnect()", 1
        )[0]
        for section in [save, connect]:
            self.assertIn("guard !nativeInventoryLoading && !duplicateNativeManagers", section)
        self.assertLess(save.index("guard !nativeInventoryLoading"),
                        save.index("selected.saveToPreferences"))
        self.assertLess(connect.index("guard !nativeInventoryLoading"),
                        connect.index("manager.connection.startVPNTunnel()"))

    def test_selector_is_generic_and_checks_all_matches(self):
        self.assertIn("for value in values where predicate(value)", SELECTOR)
        self.assertIn("if selected != nil { return .duplicate }", SELECTOR)
        self.assertIn("return .one(selected)", SELECTOR)
        self.assertIn("return .none", SELECTOR)


if __name__ == "__main__":
    unittest.main()
