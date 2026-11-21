"""ServerProfile's early public-key gate must match the strict Rust-side representation."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODEL = (ROOT / "Shared/AgentConfig.swift").read_text()
POLICY = (ROOT / "Shared/CanonicalWireGuardPublicKeyPolicy.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
XCTEST = (ROOT / "Tests/iOS/PairingTests.swift").read_text()

class ServerProfilePublicKeyBoundaryTests(unittest.TestCase):
    def test_shared_profile_guards_before_endpoint_and_digest(self):
        body = MODEL.split("func validated() throws -> ServerProfile", 1)[1].split("return self", 1)[0]
        self.assertIn("CanonicalWireGuardPublicKeyPolicy.accepts(publicKey)", body)
        self.assertLess(body.index("CanonicalWireGuardPublicKeyPolicy.accepts(publicKey)"),
                        body.index("URLComponents("))
        self.assertIn("let canonical = try validated()", MODEL)

    def test_canonical_before_decode_and_strict_key(self):
        self.assertLess(POLICY.index("value.utf8.count == 44"),
                        POLICY.index("Data(base64Encoded: value)"))
        self.assertIn("bytes.count == 32", POLICY)
        self.assertIn("bytes.base64EncodedString() == value", POLICY)
        self.assertIn("bytes.contains(where: { $0 != 0 })", POLICY)

    def test_production_swift_and_native_tests_in_required_ci(self):
        self.assertIn("Shared/CanonicalWireGuardPublicKeyPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/canonical_wireguard_public_key_smoke.swift", WORKFLOW)
        self.assertIn("testRejectsNoncanonicalOrZeroServerKeyBeforeSharedProfileStorage", XCTEST)

if __name__ == "__main__":
    unittest.main()
