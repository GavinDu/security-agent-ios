from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class MacEnrollmentSignerBoundaryTests(unittest.TestCase):
    def test_mac_only_insert_only_storage(self):
        store = (ROOT / "macos/AgentMac/MacEnrollmentSignerStore.swift").read_text()
        for token in ["kSecUseDataProtectionKeychain", "kSecAttrSynchronizable", "kSecAttrAccessibleWhenUnlockedThisDeviceOnly", "SecItemAdd(", "errSecDuplicateItem", "expectedSigner"]:
            self.assertIn(token, store)
        for forbidden in ["SecItemUpdate(", "SecItemDelete(", "kSecAttrAccessGroup", "UserDefaults(", "SharedKeychain"]:
            self.assertNotIn(forbidden, store)
        for path in (ROOT / "macos/AgentMac").glob("*.swift"):
            if path.name != "MacEnrollmentSignerStore.swift":
                self.assertNotIn("MacEnrollmentSignerStore.", path.read_text())
        self.assertIn("mac_enrollment_signer_smoke.swift", (ROOT / ".github/workflows/validate.yml").read_text())
