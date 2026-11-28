from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PeerPSKBindingBoundaryTests(unittest.TestCase):
    def test_transport_uses_exact_codec_identity_before_allocation(self):
        source = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
        self.assertNotIn("SharedKeychain.optionalPreSharedKey()", source)
        self.assertIn("serverPublicKey: profile.publicKey, clientPrivateKey: secret", source)
        self.assertLess(source.index("SharedKeychain.boundPreSharedKey("), source.index("codec = try BoringTunCodec("))
        keychain = (ROOT / "Shared/SecretStore.swift").read_text()
        self.assertIn("private static func optionalPreSharedKey()", keychain)
        self.assertIn('boundPSKAccount = "wireguard.preSharedKey.bound.v1"', keychain)
        self.assertIn("guard !legacyPresent else", keychain)
        self.assertIn("read(boundPSKAccount)", keychain)
        self.assertIn("PeerPSKBindingPolicy.select(", keychain)

    def test_regression_checks_wired(self):
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("peer_psk_binding_smoke.swift", workflow)
        self.assertTrue((ROOT / "Tests/iOS/PeerPSKBindingPolicyTests.swift").exists())

    def test_initial_stage_is_separate_insert_only_and_not_transport_visible(self):
        keychain = (ROOT / "Shared/SecretStore.swift").read_text()
        self.assertIn('pskStageAccount = "wireguard.preSharedKey.stage.v1"', keychain)
        stage = keychain.split("static func stageInitialPreSharedKey(", 1)[1].split("static func stageRotationCandidate(", 1)[0]
        for expected in ("read(pskAccount) == nil", "read(boundPSKAccount) == nil",
                         "read(rotationStageAccount) == nil", "existingIdentity()",
                         "query(pskStageAccount)", "SecItemAdd(", "errSecDuplicateItem",
                         "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", "kSecAttrSynchronizable"):
            self.assertIn(expected, stage)
        self.assertNotIn("SecItemUpdate(", stage)
        self.assertNotIn("SecItemDelete(", stage)
        for path in (ROOT / "ios").rglob("*.swift"):
            self.assertNotIn("stageInitialPreSharedKey(", path.read_text())
        select = keychain.split("static func boundPreSharedKey(", 1)[1].split("static func stageInitialPreSharedKey(", 1)[0]
        self.assertNotIn("read(pskStageAccount)", select)
