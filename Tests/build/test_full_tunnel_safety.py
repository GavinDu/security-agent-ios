"""Ensure unverified full routing cannot be activated by app or extension."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class FullTunnelSafetyTests(unittest.TestCase):
    def test_extension_enforces_before_tunnel_network_settings(self):
        source = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
        self.assertIn("TunnelRouteSafetyPolicy.permitsStart(validated.routeMode)", source)
        self.assertLess(
            source.index("TunnelRouteSafetyPolicy.permitsStart(validated.routeMode)"),
            source.index("let settings = self.networkSettings(profile: validated")
        )

    def test_app_fails_closed_before_mode_edit_and_never_forces_disconnect(self):
        source = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
        start = source.index("func changeRoute(to mode: RouteMode)")
        end = source.index("func setOnDemand(", start)
        change = source[start:end]
        self.assertLess(
            change.index("TunnelRouteSafetyPolicy.permitsStart(mode)"),
            change.index("RouteEditSafetyPolicy.permitsEdit(")
        )
        self.assertLess(
            change.index("RouteEditSafetyPolicy.permitsEdit("),
            change.index("updated.routeMode = mode")
        )
        # A stop request is asynchronous. A failed edit must never itself
        # disconnect an active safe split-tunnel connection.
        self.assertNotIn("disconnect()", change)

    def test_shared_policy_requires_explicit_security_review_to_enable(self):
        source = (ROOT / "Shared/TunnelRouteSafetyPolicy.swift").read_text()
        self.assertIn("case .split: return true", source)
        self.assertIn("case .full: return false", source)

if __name__ == "__main__":
    unittest.main()
