from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class IdentityRotationStageBoundaryTests(unittest.TestCase):
    def test_separate_insert_only_secret_account(self):
        source = (ROOT / "Shared/SecretStore.swift").read_text()
        stage = source.split("static func stageRotationCandidate", 1)[1]
        self.assertIn('rotationStageAccount = "iphone.rotation.stage.v1"', source)
        self.assertIn("query(rotationStageAccount)", stage)
        self.assertIn("SecItemAdd(", stage)
        self.assertIn("errSecDuplicateItem", stage)
        self.assertIn("existingIdentity()", stage)
        self.assertNotIn("SecItemUpdate", source)
        self.assertNotIn("SecItemDelete", stage)
        self.assertNotIn("UserDefaults(", source)
        for path in (ROOT / "ios").rglob("*.swift"):
            self.assertNotIn("stageRotationCandidate(", path.read_text())

    def test_tests_are_wired(self):
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("identity_rotation_stage_smoke.swift", workflow)
        self.assertTrue((ROOT / "Tests/iOS/IdentityRotationStagePolicyTests.swift").exists())
