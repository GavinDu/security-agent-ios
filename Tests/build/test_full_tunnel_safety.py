"""Ensure unverified full routing cannot be activated by app or extension."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class FullTunnelSafetyTests(unittest.TestCase):
    def test_extension_enforces_before_tunnel_network_settings(self):
        source = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
        self.assertIn("TunnelRouteSafetyPolicy.permitsStart(validated.routeMode)", source)
        # Network settings now throws on invalid CIDR, so preserve the
        # stronger ordering: route-mode fail-closed gate -> literal underlay
        # containment -> validated, throwing route construction.
        self.assertLess(
            source.index("TunnelRouteSafetyPolicy.permitsStart(validated.routeMode)"),
            source.index("TunnelUnderlayPolicy.permitsLiteralEndpoint(")
        )
        # DNS resolution + complete mixed-answer validation now precede
        # Keychain, Rust FFI and NetworkExtension settings, not a direct
        # networkSettings call from the original synchronous start method.
        self.assertLess(
            source.index("TunnelUnderlayPolicy.permitsLiteralEndpoint("),
            source.index("self.dnsResolver.resolve(")
        )
        self.assertLess(
            source.index("self.dnsResolver.resolve("),
            source.index("ResolvedUnderlayCandidatePolicy.selectPinnedAddress(")
        )
        self.assertLess(
            source.index("ResolvedUnderlayCandidatePolicy.selectPinnedAddress("),
            source.index("let settings = try networkSettings(profile: profile, remoteHost: pinnedHost)")
        )
        self.assertLess(
            source.index("let settings = try networkSettings(profile: profile, remoteHost: pinnedHost)"),
            source.index("provider.setTunnelNetworkSettings(settings)")
        )

    def test_app_fails_closed_before_mode_edit_or_stop_and_waits_before_save(self):
        source = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
        start = source.index("func changeRoute(to mode: RouteMode)")
        end = source.index("func setOnDemand(", start)
        change = source[start:end]
        self.assertLess(
            change.index("TunnelRouteSafetyPolicy.permitsStart(mode)"),
            change.index("RouteEditSafetyPolicy.permitsEdit(")
        )
        # Local candidate mutation is not a native write. Full-mode denial
        # must precede candidate staging AND any native stop or persistence.
        for operation in ("updated.routeMode = mode", "save(updated)",
                          "nativeIO.stop(manager)"):
            self.assertLess(change.index("TunnelRouteSafetyPolicy.permitsStart(mode)"),
                            change.index(operation))
        self.assertLess(change.index("RouteEditSafetyPolicy.permitsEdit("),
                        change.index("save(updated)"))
        self.assertLess(change.index("disconnected: nativeStatus == .disconnected"),
                        change.index("save(pending.candidate)"))
        self.assertNotIn("connectAfterSave: true", change)

    def test_shared_policy_requires_explicit_security_review_to_enable(self):
        source = (ROOT / "Shared/TunnelRouteSafetyPolicy.swift").read_text()
        self.assertIn("case .split: return true", source)
        self.assertIn("case .full: return false", source)

if __name__ == "__main__":
    unittest.main()
