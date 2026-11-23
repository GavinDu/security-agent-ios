"""Require the same nonzero private identity at both real Keychain read paths."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
KEYCHAIN = (ROOT / "Shared/SecretStore.swift").read_text()
POLICY = (ROOT / "Shared/WireGuardPrivateIdentityPolicy.swift").read_text()
SMOKE = (ROOT / "Tests/build/stored_wireguard_identity_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/WireGuardPrivateIdentityPolicyTests.swift").read_text()
CI = (ROOT / ".github/workflows/validate.yml").read_text()
PROJECT = (ROOT / "Project.swift").read_text()


class StoredIdentityKeychainBoundaryTests(unittest.TestCase):
    def test_existing_identity_read_checks_nonzero_policy(self):
        section = KEYCHAIN.split("static func existingIdentity() throws -> Data", 1)[1].split(
            "static func createIdentityIfNeeded()", 1
        )[0]
        self.assertIn("WireGuardPrivateIdentityPolicy.accepts(secret)", section)
        self.assertLess(section.index("WireGuardPrivateIdentityPolicy.accepts(secret)"),
                        section.index("return secret"))
        self.assertIn("throw KeychainError.invalidSecret", section)

    def test_create_existing_identity_fails_closed_before_new_key_generation(self):
        section = KEYCHAIN.split("static func createIdentityIfNeeded() throws -> Data", 1)[1].split(
            "static func publicKeyBase64()", 1
        )[0]
        self.assertLess(section.index("if let existing = try read(identityAccount)"),
                        section.index("WireGuardPrivateIdentityPolicy.accepts(existing)"))
        self.assertLess(section.index("WireGuardPrivateIdentityPolicy.accepts(existing)"),
                        section.index("return existing"))
        self.assertLess(section.index("WireGuardPrivateIdentityPolicy.accepts(existing)"),
                        section.index("Curve25519.KeyAgreement.PrivateKey().rawRepresentation"))
        self.assertIn("throw KeychainError.invalidSecret", section)
        self.assertIn("ImmutableIdentityInstaller.install(", section)
        self.assertNotIn("SecItemUpdate(", KEYCHAIN)

    def test_real_swift_policy_compiled_and_native_xctest_not_skipped(self):
        self.assertIn("key.count == 32 && key.contains(where: { $0 != 0 })", POLICY)
        self.assertIn("Data(repeating: 0, count: 32)", SMOKE)
        self.assertIn("Data(repeating: 0, count: 32)", NATIVE)
        self.assertIn("Tests/build/stored_wireguard_identity_smoke.swift", CI)
        self.assertIn("Shared/WireGuardPrivateIdentityPolicy.swift", CI)
        self.assertIn("python3 -m unittest discover -s Tests/build", CI)
        self.assertIn("Tuist + iOS device and simulator XCTest", CI)
        self.assertIn("Tuist + macOS companion build", CI)
        self.assertIn('sources: ["ios/AgentApp/**/*.swift", "Shared/**/*.swift"]', PROJECT)
        self.assertIn('sources: ["ios/PacketTunnel/**/*.swift", "Shared/**/*.swift"]', PROJECT)


if __name__ == "__main__":
    unittest.main()
