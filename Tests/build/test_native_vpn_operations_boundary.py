"""Verify actual TunnelManager uses the testable native I/O boundary."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
APP = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
IO = (ROOT / "ios/AgentApp/VPN/NativeVPNOperations.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/TunnelManagerNativeIntegrationTests.swift").read_text()

class NativeVPNOperationsBoundaryTests(unittest.TestCase):
    def test_production_defaults_preserve_real_native_operations(self):
        for call in ("NETunnelProviderManager.loadAllFromPreferences", ".connection.status",
                     ".connection.stopVPNTunnel()", ".connection.startVPNTunnel()",
                     ".saveToPreferences(", ".loadFromPreferences(",
                     "SharedProfileStore.load()", "SharedProfileStore.save(",
                     "SharedPreferenceWriteJournal.current"):
            self.assertIn(call, IO)
            self.assertNotIn(call, APP)
        self.assertIn("override convenience init() { self.init(nativeIO: NativeVPNOperations()) }", APP)

    def test_real_manager_integration_scenarios_exist(self):
        self.assertIn("TunnelManager(nativeIO: fake.operations())", NATIVE)
        for name in ("testActiveLegacyRouteWaitsForActualDisconnectAndNeverReconnects",
                     "testFullSelectionDoesNotStopVerifiedSplit",
                     "testLegacyOnDemandDenialAndDuplicateCallbackDoNotRetry",
                     "testRouteDeadlineCannotCommitOnLateDisconnect",
                     "testFailedReadbackCompensatesOnceWithoutReconnect",
                     "testRestartMarkerBlocksUntilExplicitRecoveryAndEmptyInventory",
                     "testLegacyConnectingReassertingAndInactiveStates",
                     "testRapidRouteSelectionsAndOfflineReassertionDoNotOverlapWrites",
                     "testDuplicateInventoryAndStaleLoadCannotAuthorizeLegacyMutation",
                     "testLegacyOnDemandSuccessRequiresFreshReadbackBeforeMigration"):
            self.assertIn(name, NATIVE)

if __name__ == "__main__":
    unittest.main()
