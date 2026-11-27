"""Explicit opt-out is isolated from generic profile mutations."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
APP = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
VIEW = (ROOT / "ios/AgentApp/VPN/VPNStatusView.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/TunnelManagerNativeIntegrationTests.swift").read_text()

class ExplicitOnDemandOptOutTests(unittest.TestCase):
    def test_narrow_authorization_and_readback_before_stop(self):
        body = APP.split("private func disableVerifiedOnDemand()", 1)[1].split("var canShowPrivateChat", 1)[0]
        for check in ("nativeInventoryTrust.permitsMutation", "prior.routeMode == .split",
                      "nativeIO.loadProfile() == prior", "nativeMatches(manager, prior)",
                      "candidate.onDemand = false"):
            self.assertIn(check, body)
        self.assertLess(body.index("preferenceJournal.begin()"), body.index("nativeInventoryTrust.beginWrite()"))
        self.assertLess(body.index("nativeInventoryTrust.beginWrite()"), body.index("manager.isOnDemandEnabled = false"))
        self.assertIn("self.nativeMatches(manager, candidate)", body)
        self.assertLess(body.index("try io.commitProfile(candidate)"), body.index("self.nativeIO.stop(manager)"))
        self.assertNotIn("nativeIO.start(", body)
        self.assertNotIn("capturePreferenceRollback", body)
        self.assertNotIn("manager.isOnDemandEnabled = true", body)
        self.assertNotIn("native.serverAddress =", body)
        failure = body.split("case .failure:", 1)[1]
        self.assertNotIn("finishPreferenceJournal", failure)
        self.assertIn("self.remediateLegacyFullTunnel()", failure)
        self.assertIn("if explicitOptOutInFlight, let prior = explicitOptOutPrior,", APP)
        self.assertIn("profile == prior, nativeIO.loadProfile() == prior", APP)
        self.assertIn("guard !explicitOptOutInFlight else {", APP)
        self.assertIn("Turning off Connect on demand also disconnects", VIEW)

    def test_actual_manager_regressions(self):
        for name in ("testOnDemandDefaultsOffAndExplicitEnableWaitsForNativeReadback",
                     "testActiveOptOutPreservesPeerAndWaitsForVerifiedDisableBeforeStop",
                     "testActiveEnableAndUntrustedOptOutDoNotMutatePreferences",
                     "testOptOutDenialOrReadbackMismatchNeverPublishesOrReenables",
                     "testOptOutTimeoutLateSaveAndReloadNeverCommitOrRetry"):
            self.assertIn(name, NATIVE)

if __name__ == "__main__":
    unittest.main()
