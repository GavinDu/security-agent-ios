"""Enforce post-native-reload comparison before App Group publication."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
APP = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
POLICY = (ROOT / "Shared/NativePreferenceCommitVerifier.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/NativePreferenceCommitVerifierTests.swift").read_text()


class NativePreferenceCommitBoundaryTests(unittest.TestCase):
    def test_after_reload_before_shared_store_commit(self):
        save = APP.split("func save(_ candidate:", 1)[1].split("func connect()", 1)[0]
        self.assertLess(save.index("selected.loadFromPreferences { error in"),
                        save.index("NativePreferenceCommitVerifier.matches("))
        self.assertLess(save.index("NativePreferenceCommitVerifier.matches("),
                        save.index("commitPublicProfile: { try SharedProfileStore.save(validated) }"))
        self.assertIn("callback(AgentConfigurationError.nativeProfileMismatch)", save)
        self.assertIn("guard error == nil else", save)
        self.assertIn("DispatchQueue.main.async", save)
        self.assertNotIn("selected.loadFromPreferences(completionHandler: callback)", save)

    def test_profile_security_fields_are_compared(self):
        for value in ("native.providerBundleIdentifier == expectedBundleID",
                      "native.serverAddress == expectedServerAddress",
                      "native.isEnabled",
                      "native.isOnDemandEnabled == expectedOnDemand",
                      "native.onDemandRuleCount == (expectedOnDemand ? 1 : 0)",
                      "NativeProfileBindingPolicy.allowsStart("):
            self.assertIn(value, POLICY)

    def test_required_native_xctest_exists(self):
        self.assertIn("testNativeOnDemandDivergenceCannotCommit", NATIVE)
        self.assertIn("testWrongProviderEndpointDigestOrDisabledNativeProfileCannotCommit", NATIVE)


if __name__ == "__main__":
    unittest.main()
