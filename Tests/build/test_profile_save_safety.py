"""Refuse native VPN writes while an existing session can retain old peers."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MANAGER = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
POLICY = (ROOT / "Shared/ProfileSaveSafetyPolicy.swift").read_text()
SMOKE = (ROOT / "Tests/build/profile_save_safety_smoke.swift").read_text()
PAIRING = (ROOT / "ios/AgentApp/Pairing/PairingView.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class ProfileSaveSafetyBoundaryTests(unittest.TestCase):
    def test_save_preflight_precedes_native_preference_mutations(self):
        save = MANAGER.split("func save(_ candidate: ServerProfile", 1)[1].split(
            "func connect()", 1
        )[0]
        self.assertIn("ProfileSaveSafetyPolicy.permitsSave(", save)
        self.assertLess(save.index("ProfileSaveSafetyPolicy.permitsSave("),
                        save.index("preferenceReloadGate.invalidate()"))
        self.assertLess(save.index("ProfileSaveSafetyPolicy.permitsSave("),
                        save.index("nativeInventoryTrust.beginWrite()"))
        self.assertLess(save.index("ProfileSaveSafetyPolicy.permitsSave("),
                        save.index("selected.protocolConfiguration = configuration"))
        self.assertIn("nativeInventoryTrust.permitsMutation", save)
        self.assertIn("manager?.connection.status", save)
        self.assertIn("manager?.isOnDemandEnabled", save)
        self.assertIn("old.publicKey != validated.publicKey", save)
        self.assertIn("old.endpoint != validated.endpoint", save)
        self.assertIn("old.routeMode != validated.routeMode", save)

    def test_pairing_keeps_preview_and_shows_native_denial(self):
        save_button = PAIRING.split('Button("Trust Mac and save VPN")', 1)[1].split(
            ".disabled(!confirmation.permitsSave(preview))", 1
        )[0]
        self.assertIn("tunnel.save(preview)", save_button)
        self.assertIn("guard macPreview == preview, confirmation.permitsSave(macPreview) else { return }", save_button)
        self.assertNotIn("macPreview = nil", save_button)
        self.assertIn(".onChange(of: tunnel.profile)", PAIRING)
        self.assertIn("if let error = tunnel.errorMessage", PAIRING)

    def test_compiled_swift_policy_is_in_required_workflow(self):
        self.assertIn("Shared/ProfileSaveSafetyPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/profile_save_safety_smoke.swift", WORKFLOW)
        self.assertIn("hasInstalledManager: true", SMOKE)
        self.assertIn("nativeOnDemandEnabled: true", SMOKE)
        self.assertIn("guard nativeDisconnected else { return false }", POLICY)


if __name__ == "__main__":
    unittest.main()
