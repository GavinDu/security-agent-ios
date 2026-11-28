from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RequiredPSKProfileBoundaryTests(unittest.TestCase):
    def test_versioned_public_digest_and_protected_save_before_native_mutation(self):
        model = (ROOT / "Shared/AgentConfig.swift").read_text()
        self.assertIn("BoundPublicProfileV2", model)
        self.assertIn("BoundPublicProfileV3", model)
        self.assertIn("let version = 3", model)
        manager = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
        save = manager.split("func save(_ candidate:", 1)[1].split("func connect()", 1)[0]
        self.assertLess(save.index("PeerPSKRequirement.permitsOrdinarySave("), save.index("preferenceJournal.begin()"))
        self.assertIn("nativeRequiresPSK: NativeProfileBindingPolicy.requiresPSK", save)
        self.assertIn("expectedProfileVersion: validated.nativeBindingVersion", save)
        extension = (ROOT / "ios/PacketTunnel/PacketTunnelProvider.swift").read_text()
        self.assertIn("expectedVersion: profile.nativeBindingVersion", extension)
        transport = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
        self.assertIn("requirement: profile.requiredPSK", transport)
        self.assertLess(transport.index("requirement: profile.requiredPSK"), transport.index("codec = try BoringTunCodec("))
        self.assertTrue((ROOT / "Tests/iOS/RequiredPSKProfileTests.swift").exists())
