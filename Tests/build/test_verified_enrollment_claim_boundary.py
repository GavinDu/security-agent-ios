from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class VerifiedEnrollmentClaimBoundaryTests(unittest.TestCase):
    def test_claim_is_insert_only_and_not_a_native_profile_mutation(self):
        source = (ROOT / "Shared/SecretStore.swift").read_text()
        claim = source.split("static func claimVerifiedEnrollmentReceipt", 1)[1].split("static func boundPreSharedKey", 1)[0]
        for token in ["wireguard.enrollment.claim.v1.", "verified.requestID.uuidString",
                      "SecItemAdd(", "errSecDuplicateItem", "kSecAttrSynchronizable",
                      "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", "existingIdentity()",
                      "profile.publicKey == verified.serverPublicKey", "profile.requiredPSK == nil",
                      "read(pskAccount) == nil", "read(boundPSKAccount) == nil",
                      "read(pskStageAccount) == nil", "read(rotationStageAccount) == nil"]:
            self.assertIn(token, claim)
        for forbidden in ["SecItemUpdate(", "SecItemDelete(", "SharedProfileStore.save(", "startVPNTunnel("]:
            self.assertNotIn(forbidden, claim)
        for path in (ROOT / "ios").rglob("*.swift"):
            self.assertNotIn("claimVerifiedEnrollmentReceipt(", path.read_text())

    def test_exact_signature_context_and_persisted_winner_required(self):
        source = (ROOT / "Shared/VerifiedEnrollmentReceiptPolicy.swift").read_text()
        for token in ["Curve25519.Signing.PublicKey", "isValidSignature(", "signingMessage(receiptBytes:",
                      "decodeUntrusted(receiptBytes)", "matchesUntrustedContext(trust.expected)",
                      "trust.signingPublicKey != serverKey", "trust.signingPublicKey != clientKey",
                      "winner == verified.record", "result == .inserted"]:
            self.assertIn(token, source)
        self.assertTrue((ROOT / "Tests/iOS/VerifiedEnrollmentReceiptPolicyTests.swift").exists())

    def test_receipt_claim_rechecks_independent_persisted_signer(self):
        source = (ROOT / "Shared/SecretStore.swift").read_text()
        verify = source.split("static func verifyEnrollmentReceipt", 1)[1].split("static func claimVerifiedEnrollmentReceipt", 1)[0]
        self.assertIn("existingEnrollmentSigningPin(", verify)
        self.assertIn("trust: .init(signingPublicKey: pin", verify)
        claim = source.split("static func claimVerifiedEnrollmentReceipt", 1)[1].split("static func boundPreSharedKey", 1)[0]
        self.assertIn("client: verified.clientPublicKey) == verified.signingPublicKey", claim)
        pin = source.split("static func installEnrollmentSigningPin", 1)[1].split("private static func existingEnrollmentSigningPin", 1)[0]
        self.assertIn("SecItemAdd(", pin)
        self.assertIn("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", pin)
        self.assertNotIn("SecItemUpdate(", pin)
        self.assertNotIn("SecItemDelete(", pin)
        for path in (ROOT / "ios").rglob("*.swift"):
            self.assertNotIn("installEnrollmentSigningPin(", path.read_text())
        self.assertTrue((ROOT / "Tests/iOS/EnrollmentSigningPinPolicyTests.swift").exists())
