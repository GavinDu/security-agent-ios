"""Protect app startup and active legacy full-route recovery from regressions."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class LegacyFullRecoveryBoundaryTests(unittest.TestCase):
    def test_reload_and_status_notifications_recover(self):
        src = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
        self.assertIn("self.remediateLegacyFullTunnel()", src)
        # An app-owned native manager can outlive an unreadable App Group profile.
        self.assertIn("guard let manager else { return }", src)
        self.assertNotIn("guard let profile, let manager else { return }", src)
        recovery = src.split("private func remediateLegacyFullTunnel()", 1)[1].split(
            "    func save(", 1
        )[0]
        # Do not trust a stale App Group split profile unless its native
        # provider bundle, endpoint and public v2 digest still agree.
        self.assertIn("native.providerBundleIdentifier == AgentConstants.tunnelBundleID", recovery)
        self.assertIn("native.serverAddress == profile.endpoint", recovery)
        self.assertIn("NativeProfileBindingPolicy.allowsStart(", recovery)
        self.assertIn("profileDigest: try? profile.publicProfileDigest()", recovery)
        self.assertIn("isFullMode: verifiedRouteIsFull", recovery)
        self.assertLess(
            recovery.index("NativeProfileBindingPolicy.allowsStart("),
            recovery.index("LegacyFullTunnelRecovery.assess("),
        )
        self.assertIn("verifiedRouteIsFull == nil", recovery)
        self.assertIn("Security Agent VPN pairing data is missing or invalid.", src)
        self.assertIn("manager.connection.stopVPNTunnel()", src)
        self.assertIn("manager.isOnDemandEnabled = false", src)
        self.assertIn("manager.onDemandRules = []", src)
        self.assertIn("legacyOnDemandDisableAttempted = true", src)
        self.assertIn("self.legacyDisableToken == disableToken", recovery)
        self.assertIn("Legacy VPN auto-connect update has not completed.", recovery)
        self.assertIn("Legacy VPN auto-connect remains enabled.", recovery)
        deadline = recovery.split("DispatchQueue.main.asyncAfter", 1)[1].split("manager.saveToPreferences", 1)[0]
        self.assertNotIn("legacyOnDemandDisableInFlight = false", deadline)
        self.assertNotIn("self.reload()", deadline)
        self.assertIn("Finish disabling legacy VPN auto-connect first.", src)
        self.assertIn("TunnelRouteSafetyPolicy.permitsStart(profile.routeMode)", src)

    def test_pure_unknown_profile_policy_runs_in_linux_and_native_xctest(self):
        policy = (ROOT / "Shared/LegacyFullTunnelRecovery.swift").read_text()
        smoke = (ROOT / "Tests/build/legacy_full_tunnel_recovery_smoke.swift").read_text()
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("isFullMode: Bool?", policy)
        self.assertIn("guard isFullMode != false", policy)
        self.assertIn("isFullMode: nil", smoke)
        self.assertIn("legacy_full_tunnel_recovery_smoke.swift", workflow)
        self.assertTrue((ROOT / "Tests/iOS/LegacyFullTunnelRecoveryTests.swift").exists())

    def test_ui_does_not_claim_unsafe_full_tunnel_is_connected(self):
        src = (ROOT / "ios/AgentApp/VPN/VPNStatusView.swift").read_text()
        self.assertIn("This saved full-tunnel profile is blocked for safety.", src)
        self.assertIn(".disabled(profile.routeMode == .full)", src)

if __name__ == "__main__":
    unittest.main()
