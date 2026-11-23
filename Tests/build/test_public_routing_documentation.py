"""Keep public VPN routing documentation aligned with production Swift gates.

Discovered by the mandatory Linux unittest job; native XCTests remain required.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PublicRoutingDocumentationTests(unittest.TestCase):
    def test_full_tunnel_fails_closed_in_app_and_extension(self):
        policy = (ROOT / "Shared/TunnelRouteSafetyPolicy.swift").read_text()
        app = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
        extension = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
        self.assertIn("case .split: return true", policy)
        self.assertIn("case .full: return false", policy)
        self.assertIn("TunnelRouteSafetyPolicy.permitsStart(mode)", app)
        self.assertIn("TunnelRouteSafetyPolicy.permitsStart(profile.routeMode)", app)
        self.assertIn(
            "TunnelRouteSafetyPolicy.permitsStart(validated.routeMode)", extension
        )

    def test_readme_describes_unsigned_build_and_split_only_runtime(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("**Active routing: split-only.**", readme)
        self.assertIn("both reject full-tunnel", readme)
        self.assertIn("do not treat it as a device-wide kill switch", " ".join(readme.split()))
        self.assertIn("CI-verified unsigned Foundation", readme)
        self.assertIn("45060469690", readme)
        self.assertIn("real Mac peer", readme)
        self.assertNotIn("**Status (initial scaffold):**", readme)
        self.assertNotIn("Full tunnel\n  configures", readme)
        self.assertNotIn("Split/full routing mode toggle", readme)

    def test_native_guide_and_roadmap_distinguish_unverified_full_mode(self):
        guide = (ROOT / "docs/BORINGTUN_BUILD.md").read_text()
        roadmap = (ROOT / "docs/ROADMAP.md").read_text()
        self.assertIn("Do not test or advertise full tunnel as enabled", guide)
        self.assertIn("in both the app and the extension", guide)
        self.assertIn("signed-device Mac/iPhone evidence", guide)
        self.assertIn("app *and extension* reject full-tunnel activation", roadmap)
        self.assertIn("Split mode remains enabled", roadmap)

    def test_mandatory_ci_executes_guard_and_preserves_native_jobs(self):
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("python3 -m unittest discover -s Tests/build", workflow)
        self.assertIn("Tuist + iOS device and simulator XCTest", workflow)
        self.assertIn("Tuist + macOS companion build", workflow)


if __name__ == "__main__":
    unittest.main()
