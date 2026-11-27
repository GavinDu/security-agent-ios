from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PublicPeerInventoryBoundaryTests(unittest.TestCase):
    def test_parser_does_not_execute_or_log_commands(self):
        source = (ROOT / "Shared/MacPeerPublicInventory.swift").read_text()
        for forbidden in ("Process(", "NSTask", "system(", "print(", "NSLog(", "FileHandle"):
            self.assertNotIn(forbidden, source)
        self.assertIn("server == [expectedServerKey]", source)
        self.assertIn("parsed == declared", source)
        self.assertIn("slots.insert(slot).inserted", source)
        self.assertIn("Set([peer.ipv4CIDR, peer.ipv6CIDR])", source)

    def test_parser_is_tested_but_not_live_daemon_authority(self):
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("mac_peer_public_inventory_smoke.swift", workflow)
        self.assertTrue((ROOT / "Tests/iOS/MacPeerPublicInventoryTests.swift").exists())
        for parent in ("macos", "ios"):
            for path in (ROOT / parent).rglob("*.swift"):
                self.assertNotIn("MacPeerPublicInventory.decode", path.read_text())
