"""Mac WireGuard per-peer address proposal must not silently reuse a slot."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "Shared/MacPeerAddressAllocationPolicy.swift").read_text()
MAC = (ROOT / "macos/AgentMac/MacDashboard.swift").read_text()
WF = (ROOT / ".github/workflows/validate.yml").read_text()
SWIFT = (ROOT / "Tests/build/mac_peer_address_allocation_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/MacPeerAddressAllocationPolicyTests.swift").read_text()


class MacPeerAllocationBoundaryTests(unittest.TestCase):
    def test_reject_duplicates_before_new_reservation(self):
        for token in [
            "IPhonePairingImportPolicy.validatedPublicKey(publicKey)",
            "IPhonePairingImportPolicy.validatedPublicKey(reservation.publicKey)",
            "existing.count < maxClients", "keys.insert(reservation.publicKey).inserted",
            "slots.insert(reservation.slot).inserted", "!keys.contains(publicKey)",
        ]:
            self.assertIn(token, POLICY)
        self.assertLess(POLICY.index("slots.insert(reservation.slot).inserted"),
                        POLICY.index("for number in Int(firstClient)"))

    def test_no_unsafe_mac_provisioning_claim_and_required_swift_tests(self):
        self.assertIn("This UI does not run sudo", MAC)
        self.assertIn("Shared/MacPeerAddressAllocationPolicy.swift", WF)
        self.assertIn("Tests/build/mac_peer_address_allocation_smoke.swift", WF)
        self.assertIn("testTwoDifferentCanonicalPeersReceiveDistinctIPv4AndIPv6", NATIVE)
        self.assertIn("Fully reserved block", SWIFT)

if __name__ == "__main__":
    unittest.main()
