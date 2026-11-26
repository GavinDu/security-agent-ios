"""Require native-disconnected and on-demand-off before route preference edits."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class RouteEditBoundaryTests(unittest.TestCase):
    def test_change_route_waits_for_native_acknowledgement_before_save(self):
        src = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
        start = src.index("func changeRoute(to mode: RouteMode)")
        stop = src.index("func setOnDemand(", start)
        section = src[start:stop]
        self.assertIn("nativeStatus == .disconnected || (manager == nil && nativeStatus == .invalid)", section)
        self.assertIn("manager?.isOnDemandEnabled ?? false", section)
        self.assertIn("legacyOnDemandDisableInFlight", section)
        self.assertIn("RouteEditSafetyPolicy.permitsEdit(", section)
        self.assertLess(section.index("RouteEditSafetyPolicy.permitsEdit("),
                        section.index("save(updated)"))
        self.assertLess(section.index("pendingRoute = PendingRoute("),
                        section.index("manager.connection.stopVPNTunnel()"))
        self.assertIn("routeStop.cancel(token)", section)
        self.assertIn("manager === pending.manager", section)
        self.assertIn("profile == pending.original", section)
        self.assertIn("SharedProfileStore.load() == pending.original", section)
        self.assertIn("SharedProfileStore.load() == original", section)
        self.assertIn("let nativeDisconnected = nativeStatus == .disconnected || (manager == nil && nativeStatus == .invalid)", src)
        self.assertIn("disconnected: nativeStatus == .disconnected", section)
        self.assertLess(section.index("case .commit:"), section.index("save(pending.candidate)"))
        self.assertNotIn("connectAfterSave: true", section)
        self.assertIn("self.advanceRouteChange()", src)
        self.assertIn("updated.onDemand = false", section)
        self.assertNotIn("disconnect()", section)

    def test_denied_legacy_disable_also_refreshes_native_manager(self):
        src = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
        start = src.index("manager.saveToPreferences { [weak self] error in")
        stop = src.index("\n    func save(", start)
        callback = src[start:stop]
        self.assertIn("self.reload()", callback)
        self.assertIn("if let error", callback)
        self.assertIn("self.legacyDisableToken == disableToken", callback)
        self.assertIn("self.manager === manager", callback)
        self.assertLess(callback.index("if let error"), callback.index("self.reload()"))

if __name__ == "__main__":
    unittest.main()
