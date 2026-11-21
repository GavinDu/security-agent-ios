"""Block duplicate JSON keys in iPhone scanned Mac QR before parsing."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "Shared/MacPairingQRInputPolicy.swift").read_text()
PARSER = (ROOT / "Shared/UniqueFlatJSONObjectPolicy.swift").read_text()
CONFIG = (ROOT / "Shared/AgentConfig.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()

class UniqueMacQrJSONBoundaryTests(unittest.TestCase):
    def test_unique_key_check_precedes_first_json_parser(self):
        self.assertLess(POLICY.index("text.utf8.count <= maxPayloadBytes"),
                        POLICY.index("let data = Data(text.utf8)"))
        self.assertLess(POLICY.index("UniqueFlatJSONObjectPolicy.hasUniqueStringKeys(data)"),
                        POLICY.index("JSONSerialization.jsonObject(with: data)"))
        self.assertIn("seen.contains(key)", PARSER)
        self.assertIn("JSONDecoder().decode(", PARSER)
        self.assertIn("Data(bytes[start..<cursor])", PARSER)
        self.assertIn("return cursor == count", PARSER)
        self.assertIn("guard scalarValue()", PARSER)
    def test_original_fingerprint_confirmation_and_endpoint_safety_retained(self):
        self.assertIn("MacPairingQRInputPolicy.decode(text)", CONFIG)
        self.assertIn("ServerProfile(publicKey: fields.publicKey, endpoint: fields.endpoint).validated()", CONFIG)
    def test_real_swift_smoke_and_native_xctest_in_ci(self):
        self.assertIn("Shared/UniqueFlatJSONObjectPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/unique_flat_json_root_smoke.swift", WORKFLOW)
        self.assertTrue((ROOT / "Tests/iOS/UniqueFlatJSONObjectPolicyTests.swift").exists())

if __name__ == "__main__":
    unittest.main()
