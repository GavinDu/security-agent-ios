"""iPhone Mac pairing QR must be bounded and validated before profile trust."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "Shared/MacPairingQRInputPolicy.swift").read_text()
CONFIG = (ROOT / "Shared/AgentConfig.swift").read_text()
UI = (ROOT / "ios/AgentApp/Pairing/PairingView.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()

class MacPairingQRInputBoundaryTests(unittest.TestCase):
    def test_size_cap_precedes_data_allocation_and_json_parsing(self):
        self.assertLess(POLICY.index("text.utf8.count <= maxPayloadBytes"),
                        POLICY.index("let data = Data(text.utf8)"))
        self.assertLess(POLICY.index("let data = Data(text.utf8)"),
                        POLICY.index("JSONSerialization.jsonObject(with: data)"))
        self.assertIn('Set(dictionary.keys) == Set(["version", "kind", "publicKey", "endpoint"])', POLICY)
        self.assertIn("bytes.base64EncodedString() == payload.publicKey", POLICY)
        self.assertIn("bytes.contains(where: { $0 != 0 })", POLICY)
    def test_real_scan_requires_policy_and_existing_profile_validation(self):
        decoded = CONFIG.split("static func decodeMac(_ text: String)", 1)[1]
        self.assertIn("MacPairingQRInputPolicy.decode(text)", decoded)
        self.assertIn("ServerProfile(publicKey: fields.publicKey, endpoint: fields.endpoint).validated()", decoded)
        self.assertNotIn("JSONDecoder().decode(PairingQRCode.self, from: Data(text.utf8))", decoded)
        self.assertIn("guard fingerprintConfirmed else { return }", UI)
        self.assertIn(".disabled(!fingerprintConfirmed)", UI)
    def test_executed_swift_and_native_tests(self):
        self.assertIn("Shared/MacPairingQRInputPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/mac_pairing_qr_input_smoke.swift", WORKFLOW)
        self.assertTrue((ROOT / "Tests/iOS/MacPairingQRInputPolicyTests.swift").exists())

if __name__ == "__main__":
    unittest.main()
