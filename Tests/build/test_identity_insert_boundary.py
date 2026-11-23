"""Guard immutable shared WireGuard identity creation at the Keychain boundary."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
KEYCHAIN = (ROOT / "Shared/SecretStore.swift").read_text()
INSTALLER = (ROOT / "Shared/ImmutableIdentityInstaller.swift").read_text()
SMOKE = (ROOT / "Tests/build/immutable_identity_installer_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/ImmutableIdentityInstallerTests.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class ImmutableIdentityKeychainBoundaryTests(unittest.TestCase):
    def test_atomic_add_and_duplicate_read_not_upsert(self):
        section = KEYCHAIN.split("static func createIdentityIfNeeded()", 1)[1].split(
            "static func publicKeyBase64()", 1
        )[0]
        self.assertIn("ImmutableIdentityInstaller.install(", section)
        self.assertIn("SecItemAdd(", section)
        self.assertIn("errSecDuplicateItem", section)
        self.assertIn("return .alreadyExists", section)
        self.assertIn("readExisting: { try read(identityAccount) }", section)
        self.assertNotIn("SecItemUpdate", KEYCHAIN)
        self.assertNotIn("write(privateKey", section)
        self.assertIn("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", section)

    def test_zero_candidate_and_duplicate_winner_rejected_before_return(self):
        self.assertIn("candidate.contains(where: { $0 != 0 })", INSTALLER)
        self.assertIn("winner.contains(where: { $0 != 0 })", INSTALLER)
        self.assertLess(
            INSTALLER.index("guard candidate.count == 32"),
            INSTALLER.index("switch try insertIfAbsent(candidate)"),
        )
        self.assertLess(
            INSTALLER.index("guard winner.count == 32"),
            INSTALLER.index("return winner"),
        )
        self.assertIn("Data(repeating: 0, count: 32)", SMOKE)
        self.assertIn("zero identity inserted", SMOKE)
        self.assertIn("testZeroSecretCandidateNeverReachesAtomicInsert", NATIVE)
        self.assertIn("testZeroSecretConcurrentKeychainWinnerFailsClosed", NATIVE)
        self.assertIn("Shared/ImmutableIdentityInstaller.swift", WORKFLOW)
        self.assertIn("Tests/build/immutable_identity_installer_smoke.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("Tuist + macOS companion build", WORKFLOW)

    def test_share_group_and_secret_storage_separation(self):
        self.assertIn("AgentConstants.appGroup", KEYCHAIN)
        self.assertIn("kSecAttrAccessGroup", KEYCHAIN)
        self.assertIn("iphone.privateKey", KEYCHAIN)
        self.assertIn("privateKey", KEYCHAIN)
        self.assertNotIn("UserDefaults(", KEYCHAIN)
        self.assertIn("case .alreadyExists:", INSTALLER)
        self.assertIn("return winner", INSTALLER)
        self.assertIn("winner.count == 32", INSTALLER)


if __name__ == "__main__":
    unittest.main()
