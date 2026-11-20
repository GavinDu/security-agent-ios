"""Require native-disconnected and on-demand-off before route preference edits."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class RouteEditBoundaryTests(unittest.TestCase):
    def test_change_route_guards_before_mutation_and_never_auto_disconnects(self):
        src = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
        start = src.index("func changeRoute(to mode: RouteMode)")
        stop = src.index("func setOnDemand(", start)
        section = src[start:stop]
        self.assertIn("nativeStatus == .disconnected || nativeStatus == .invalid", section)
        self.assertIn("manager?.isOnDemandEnabled ?? false", section)
        self.assertIn("legacyOnDemandDisableInFlight", section)
        self.assertIn("RouteEditSafetyPolicy.permitsEdit(", section)
        self.assertLess(
            section.index("RouteEditSafetyPolicy.permitsEdit("),
            section.index("updated.routeMode = mode")
        )
        self.assertIn("updated.onDemand = false", section)
        self.assertNotIn("disconnect()", section)

    def test_denied_legacy_disable_also_refreshes_native_manager(self):
        src = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
        start = src.index("manager.saveToPreferences { [weak self] error in")
        stop = src.index("\n    func save(", start)
        callback = src[start:stop]
        self.assertIn("self.reload()", callback)
        self.assertIn("if let error", callback)
        self.assertLess(callback.index("if let error"), callback.index("self.reload()"))

if __name__ == "__main__":
    unittest.main()
