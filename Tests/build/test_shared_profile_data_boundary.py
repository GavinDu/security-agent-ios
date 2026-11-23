"""Guard public App Group profile sizes before JSON decode or persist."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "Shared/AgentConfig.swift").read_text()
POLICY = (ROOT / "Shared/SharedProfileDataPolicy.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/SharedProfileDataPolicyTests.swift").read_text()
SMOKE = (ROOT / "Tests/build/shared_profile_data_smoke.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
PROJECT = (ROOT / "Project.swift").read_text()


class BoundedPublicProfileDataTests(unittest.TestCase):
    def test_read_bound_precedes_production_json_decode(self):
        store = SOURCE.split("enum SharedProfileStore {", 1)[1]
        load = store.split("static func load() -> ServerProfile?", 1)[1].split(
            "static func save(", 1
        )[0]
        self.assertLess(
            load.index("SharedProfileDataPolicy.accepts(bytes)"),
            load.index("JSONDecoder().decode(ServerProfile.self, from: bytes)"),
        )
        self.assertIn("else { return nil }", load)
        self.assertIn(".validated()", load)

    def test_write_bound_precedes_public_profile_commit(self):
        save = SOURCE.split("static func save(_ profile: ServerProfile)", 1)[1]
        self.assertLess(
            save.index("let validated = try profile.validated()"),
            save.index("let bytes = try JSONEncoder().encode(validated)"),
        )
        self.assertLess(
            save.index("SharedProfileDataPolicy.accepts(bytes)"),
            save.index("defaults.set(bytes, forKey: key)"),
        )
        self.assertIn("throw AgentConfigurationError.invalidProfileData", save)
        self.assertIn("case .invalidProfileData: return", SOURCE)

    def test_exact_policy_is_compiled_and_exercised_in_native_ci(self):
        self.assertIn("static let maxEncodedBytes = 4_096", POLICY)
        self.assertIn("count > 0 && count <= maxEncodedBytes", POLICY)
        for example in ["4_096", "4_097", "Int.max"]:
            self.assertIn(example, SMOKE)
            self.assertIn(example, NATIVE)
        self.assertIn("testPublicProfileCanonicalEncodingFitsLimit", NATIVE)
        self.assertIn("Shared/SharedProfileDataPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/shared_profile_data_smoke.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("Tuist + macOS companion build", WORKFLOW)
        self.assertIn('sources: ["ios/AgentApp/**/*.swift", "Shared/**/*.swift"]', PROJECT)
        self.assertIn('sources: ["ios/PacketTunnel/**/*.swift", "Shared/**/*.swift"]', PROJECT)


if __name__ == "__main__":
    unittest.main()
