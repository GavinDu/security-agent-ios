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

    def test_roster_transactions_are_isolated_and_not_live_provisioning(self):
        for token in ["actor MacPeerRosterCoordinator", "pending == nil",
                      "current == expected", "current.revision < UInt64.max",
                      "proposed.firstIndex(of: exactPeer)", "plan.id == id",
                      "canonical == plan.after", "canonical == plan.before.peers",
                      "revision: current.revision + 1"]:
            self.assertIn(token, POLICY)
        self.assertIn("testConcurrentEnrollmentAndReadback", NATIVE)
        self.assertIn("testExactRevokeAndRollbackInvalidateSnapshot", NATIVE)
        self.assertIn("testCorruptRosterOverflowAndDifferentEpoch", NATIVE)
        self.assertIn("Mac peer roster serialization and readback transaction policy passed", SWIFT)
        self.assertNotIn("MacPeerRosterCoordinator", MAC)
        self.assertIn("Single-device preview", MAC)

    def test_durable_roster_blocks_unfenced_recovery_and_stale_writes(self):
        for token in ["MacPeerRosterJournal", "persistenceBlocked = true",
                      "guard persist(next: current, pending: plan)",
                      "guard persist(next: next, pending: nil)",
                      "journal == nil || terminalWriteFenced",
                      "flock(fd, LOCK_EX | LOCK_NB)", "guard try read() == expected",
                      "options: .withoutOverwriting", "options: .atomic",
                      "try sync(file)", "try sync(directory)", "O_NOFOLLOW",
                      "try encode(record) == bytes"]:
            self.assertIn(token, POLICY)
        self.assertIn("testDurableRosterRestartAndFencedRecovery", NATIVE)
        self.assertIn("testDurableRosterRejectsMissingOrOversizedRecordAndUnsafeDirectory", NATIVE)
        self.assertIn("Durable peer roster journal restart and fenced readback passed", SWIFT)
        self.assertIn("owner == UInt32(geteuid())", POLICY)
        self.assertIn("info.st_nlink == 1", POLICY)
        self.assertIn("testDurableRosterWriteFailureBlocksAndDoesNotBootstrap", NATIVE)
        self.assertIn("testDurableRosterRejectsUnknownFieldsAndWrongLockMode", NATIVE)
        self.assertNotIn("MacPeerRosterJournal", MAC)

    def test_no_unsafe_mac_provisioning_claim_and_required_swift_tests(self):
        self.assertIn("This UI does not run sudo", MAC)
        self.assertIn("Shared/MacPeerAddressAllocationPolicy.swift", WF)
        self.assertIn("Tests/build/mac_peer_address_allocation_smoke.swift", WF)
        self.assertIn("testTwoDifferentCanonicalPeersReceiveDistinctIPv4AndIPv6", NATIVE)
        self.assertIn("Fully reserved block", SWIFT)

if __name__ == "__main__":
    unittest.main()
