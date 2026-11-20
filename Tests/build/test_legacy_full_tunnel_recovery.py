"""Protect app startup and active legacy full-route recovery from regressions."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class LegacyFullRecoveryBoundaryTests(unittest.TestCase):
    def test_reload_and_status_notifications_recover(self):
        src = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
        self.assertIn("self.remediateLegacyFullTunnel()", src)
        self.assertIn("manager.connection.stopVPNTunnel()", src)
        self.assertIn("manager.isOnDemandEnabled = false", src)
        self.assertIn("manager.onDemandRules = []", src)
        self.assertIn("legacyOnDemandDisableAttempted = true", src)
        self.assertIn("Finish disabling legacy VPN auto-connect first.", src)
        self.assertIn("TunnelRouteSafetyPolicy.permitsStart(profile.routeMode)", src)

    def test_ui_does_not_claim_unsafe_full_tunnel_is_connected(self):
        src = (ROOT / "ios/AgentApp/VPN/VPNStatusView.swift").read_text()
        self.assertIn("This saved full-tunnel profile is blocked for safety.", src)
        self.assertIn(".disabled(profile.routeMode == .full)", src)

if __name__ == "__main__":
    unittest.main()
