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
