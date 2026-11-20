"""Ensure public-profile binding is checked before native Rust VPN start."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
APP = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
EXT = (ROOT / "ios/PacketTunnel/PacketTunnelProvider.swift").read_text()
PROFILE = (ROOT / "Shared/AgentConfig.swift").read_text()
POLICY = (ROOT / "Shared/NativeProfileBindingPolicy.swift").read_text()


class NativeProfileBindingBoundaryTests(unittest.TestCase):
    def test_canonical_public_digest_and_no_secret_material(self):
        portion = PROFILE.split("func publicProfileDigest()", 1)[1].split(
            "func publicKeyFingerprint()", 1
        )[0]
        self.assertIn("let canonical = try validated()", portion)
        self.assertIn("encoder.outputFormatting = [.sortedKeys]", portion)
        self.assertIn("SHA256.hash(data: bytes)", portion)
        self.assertNotIn("SharedKeychain", portion)
        self.assertNotIn("presharedKey", portion)
        self.assertNotIn("privateKey", portion)

    def test_app_persists_digest_before_saving_preferences(self):
        saving = APP.split("func save(_ candidate:", 1)[1].split(
            "func connect()", 1
        )[0]
        self.assertLess(saving.index("bindingDigest = try validated.publicProfileDigest()"),
                        saving.index("selected.saveToPreferences"))
        self.assertLess(saving.index("NativeProfileBindingPolicy.metadata(for: bindingDigest)"),
                        saving.index("selected.saveToPreferences"))
        self.assertNotIn('"privateKey"', saving)
        self.assertNotIn('"presharedKey"', saving)

    def test_app_checks_metadata_before_user_start(self):
        connection = APP.split("func connect()", 1)[1].split(
            "func disconnect()", 1
        )[0]
        self.assertLess(connection.index("NativeProfileBindingPolicy.allowsStart("),
                        connection.index("manager.connection.startVPNTunnel()"))
        self.assertIn("nativeProfileMismatch", connection)

    def test_extension_refuses_drift_before_engine_construction(self):
        starting = EXT.split("override func startTunnel(", 1)[1].split(
            "override func stopTunnel(", 1
        )[0]
        self.assertLess(starting.index("NativeProfileBindingPolicy.allowsStart("),
                        starting.index("BoringTunTransport(provider: self)"))
        self.assertIn("completionHandler(AgentConfigurationError.nativeProfileMismatch)", starting)
        self.assertIn("self.lifecycle.finishStart(success: false)", starting)
        self.assertNotIn("BoringTunCodec(", starting)

    def test_policy_is_exact_and_fail_closed(self):
        self.assertIn("static let requiredVersion = 2", POLICY)
        self.assertIn("decoded.count == 32", POLICY)
        self.assertIn("return stored == expected", POLICY)
        self.assertNotIn("UserDefaults", POLICY)


if __name__ == "__main__":
    unittest.main()
