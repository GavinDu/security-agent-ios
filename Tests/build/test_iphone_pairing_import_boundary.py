"""Mac companion's non-camera pairing is bounded and fail closed."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MAC = (ROOT / "macos/AgentMac/MacDashboard.swift").read_text()
POLICY = (ROOT / "Shared/IPhonePairingImportPolicy.swift").read_text()
WF = (ROOT / ".github/workflows/validate.yml").read_text()

class MacPairingImportBoundaryTests(unittest.TestCase):
    def test_mac_uses_same_shared_qr_and_manual_peer_validation(self):
        self.assertRegex(MAC, r"IPhonePairingImportPolicy\.decodePublicKey\(\s*from:\s*iphonePairingText\s*\)")
        self.assertIn("IPhonePairingImportPolicy.validatedPublicKey(iphonePublicKey)", MAC)
        self.assertIn(".disabled(validatedIPhoneKey == nil)", MAC)
        self.assertNotIn("JSONDecoder().decode(", MAC)
        self.assertNotIn("error.localizedDescription", MAC)
    def test_validator_is_strict_and_bounded(self):
        self.assertIn("maxPayloadBytes = 4_096", POLICY)
        self.assertIn("bytes.count <= maxPayloadBytes", POLICY)
        self.assertIn('payload.kind == "iphone"', POLICY)
        self.assertIn('Set(dictionary.keys) == Set(["version", "kind", "publicKey"])', POLICY)
        self.assertIn("UniqueFlatJSONObjectPolicy.hasUniqueStringKeys(bytes)", POLICY)
        self.assertLess(POLICY.index("text.utf8.count <= maxPayloadBytes"),
                        POLICY.index("let bytes = Data(text.utf8)"))
        self.assertLess(POLICY.index("UniqueFlatJSONObjectPolicy.hasUniqueStringKeys(bytes)"),
                        POLICY.index("JSONSerialization.jsonObject(with: bytes)"))
        self.assertIn("value.utf8.count == 44", POLICY)
        self.assertIn("bytes.base64EncodedString() == value", POLICY)
        self.assertIn("bytes.contains(where: { $0 != 0 })", POLICY)
    def test_actual_swift_and_native_tests_required(self):
        self.assertIn("Shared/IPhonePairingImportPolicy.swift", WF)
        self.assertIn("Tests/build/iphone_pairing_import_smoke.swift", WF)
        self.assertTrue((ROOT / "Tests/iOS/IPhonePairingImportPolicyTests.swift").exists())

if __name__ == "__main__":
    unittest.main()
