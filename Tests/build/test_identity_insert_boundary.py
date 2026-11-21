"""Guard immutable shared WireGuard identity creation at the Keychain boundary."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
KEYCHAIN = (ROOT / "Shared/SecretStore.swift").read_text()
INSTALLER = (ROOT / "Shared/ImmutableIdentityInstaller.swift").read_text()


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
