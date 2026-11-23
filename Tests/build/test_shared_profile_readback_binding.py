"""Public App Group VPN save must detect mismatched immediate readback."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROFILE = (ROOT / "Shared/AgentConfig.swift").read_text()
POLICY = (ROOT / "Shared/SharedProfileReadbackPolicy.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
NATIVE = (ROOT / "Tests/iOS/SharedProfileReadbackTests.swift").read_text()
MANAGER = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()


class SharedProfileReadbackBindingTests(unittest.TestCase):
    def test_actual_public_store_binds_readback_to_throwing_save(self):
        store = PROFILE.split("enum SharedProfileStore {", 1)[1]
        saving = store.split("static func save(_ profile: ServerProfile) throws {", 1)[1]
        self.assertIn("let validated = try profile.validated()", saving)
        self.assertIn("SharedProfileDataPolicy.accepts(bytes)", saving)
        self.assertIn("defaults.set(bytes, forKey: key)", saving)
        self.assertIn("SharedProfileReadbackPolicy.accepts(", saving)
        self.assertIn("expected: bytes, observed: defaults.data(forKey: key)", saving)
        self.assertLess(
            saving.index("defaults.set(bytes, forKey: key)"),
            saving.index("expected: bytes, observed: defaults.data(forKey: key)")
        )
        self.assertIn("throw AgentConfigurationError.invalidProfileData", saving)
        self.assertIn("case .failure(let error):", MANAGER)
        self.assertIn("commitPublicProfile: { try SharedProfileStore.save(validated) }", MANAGER)

    def test_policy_is_bounded_public_data_only_and_tests_are_mandatory(self):
        self.assertIn("SharedProfileDataPolicy.accepts(expected)", POLICY)
        self.assertIn("SharedProfileDataPolicy.accepts(observed)", POLICY)
        self.assertIn("return observed == expected", POLICY)
        self.assertNotIn("Keychain", POLICY)
        self.assertIn("func testMatchingAndChangedPublicProfileBytes()", NATIVE)
        self.assertIn("func testBoundsAreReappliedToReadback()", NATIVE)
        self.assertIn("Shared/SharedProfileReadbackPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/shared_profile_readback_smoke.swift", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("Tuist + macOS companion build", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
