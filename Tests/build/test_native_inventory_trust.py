"""Fail-closed native VPN manager inventory trust and lifecycle wiring."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
TRUST = (ROOT / "ios/AgentApp/VPN/NativeVPNInventoryTrust.swift").read_text()
VIEW = (ROOT / "ios/AgentApp/VPN/VPNStatusView.swift").read_text()


class NativeInventoryTrustBoundaryTests(unittest.TestCase):
    def test_failed_read_remains_blocked_after_failure(self):
        load = SOURCE.split("func reload() {", 1)[1].split(
            "/// Stop any inherited full-tunnel session", 1
        )[0]
        self.assertIn("nativeInventoryTrust.beginLoad()", load)
        self.assertIn("case .reportFailure:", load)
        self.assertIn("self.nativeInventoryTrust.didFailLoad()", load)
        self.assertIn("case .discard:", load)
        self.assertIn("return", load)
        self.assertIn("self.nativeInventoryTrust.didLoadDuplicateInventory()", load)
        self.assertIn("self.nativeInventoryTrust.didLoadUniqueInventory()", load)
        self.assertLess(load.index("preferenceReloadGate.disposition("),
                        load.index("self.nativeInventoryTrust.didFailLoad()"))

    def test_writes_and_connects_need_verified_inventory(self):
        save = SOURCE.split("func save(_ candidate:", 1)[1].split("func connect()", 1)[0]
        connect = SOURCE.split("func connect()", 1)[1].split("func disconnect()", 1)[0]
        for block in (save, connect):
            self.assertIn("guard nativeInventoryTrust.permitsMutation else", block)
        self.assertLess(save.index("nativeInventoryTrust.beginWrite()"),
                        save.index("io.save(selected"))
        self.assertLess(save.index("nativeInventoryTrust.didCommitVerifiedWrite()"),
                        save.index("if connectAfterSave { self.connect() }"))
        self.assertLess(connect.index("nativeInventoryTrust.permitsMutation"),
                        connect.index("nativeIO.start(manager)"))

    def test_legacy_mutation_invalidates_trust_and_reloads(self):
        legacy = SOURCE.split("private func remediateLegacyFullTunnel()", 1)[1].split(
            "func save(_ candidate:", 1
        )[0]
        self.assertLess(legacy.index("nativeInventoryTrust.beginWrite()"),
                        legacy.index("nativeIO.save(manager)"))
        self.assertIn("self.reload()", legacy)
        self.assertIn("Retry loading VPN preferences", VIEW)

    def test_only_confirmed_state_permises_operations(self):
        self.assertIn("var permitsMutation: Bool { state == .verified }", TRUST)
        self.assertIn("guard state == .loading else { return }", TRUST)
        self.assertIn("guard state == .unverified else { return }", TRUST)
        self.assertIn("state = .failed", TRUST)
        self.assertIn("state = .ambiguous", TRUST)


if __name__ == "__main__":
    unittest.main()
