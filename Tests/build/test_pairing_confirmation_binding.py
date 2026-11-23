"""Guard the production QR preview-to-save confirmation binding."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
GATE = (ROOT / "Shared/PairingConfirmationGate.swift").read_text()
UI = (ROOT / "ios/AgentApp/Pairing/PairingView.swift").read_text()
TEST = (ROOT / "Tests/build/pairing_confirmation_smoke.swift").read_text()
IOS = (ROOT / "Tests/iOS/PairingTests.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
PROJECT = (ROOT / "Project.swift").read_text()


class PairingConfirmationBindingTests(unittest.TestCase):
    def test_ui_save_checks_exact_confirmed_profile(self):
        self.assertIn("PairingConfirmationGate<ServerProfile>()", UI)
        self.assertIn("confirmation.setConfirmed(newValue, for: macPreview)", UI)
        self.assertIn("guard confirmation.permitsSave(preview) else { return }", UI)
        self.assertIn(".disabled(!confirmation.permitsSave(preview))", UI)
        self.assertNotIn("@State private var fingerprintConfirmed = false", UI)
        self.assertGreaterEqual(UI.count("confirmation.reset()"), 2)
        self.assertIn("return confirmedProfile == preview", GATE)
        self.assertIn("guard let preview, let confirmedProfile else { return false }", GATE)

    def test_real_linux_and_native_tests_are_wired(self):
        self.assertIn("Tests/build/pairing_confirmation_smoke.swift", WORKFLOW)
        self.assertIn("Shared/PairingConfirmationGate.swift", WORKFLOW)
        self.assertIn("testFingerprintConfirmationBindsExactPublicProfile", IOS)
        self.assertIn("gate.setConfirmed(true, for: original)", TEST)
        self.assertIn("routeMode: \"full\"", TEST)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn('sources: ["ios/AgentApp/**/*.swift", "Shared/**/*.swift"]', PROJECT)


if __name__ == "__main__":
    unittest.main()
