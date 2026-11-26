"""Production wiring for one-shot verified native compensation."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
APP = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()

class RollbackBoundaryTests(unittest.TestCase):
    def test_capture_before_mutation_and_reconcile_after_fresh_inventory(self):
        save = APP.split("func save(_ candidate:", 1)[1].split("func connect()", 1)[0]
        self.assertLess(save.index("capturePreferenceRollback(to: validated)"),
                        save.index("nativeInventoryTrust.beginWrite()"))
        self.assertIn("self.pendingPreferenceRollback = rollbackPlan", save)
        self.assertIn("if !self.profileSave.isAwaitingNativeCompletion", save)
        reload = APP.split("func reload()", 1)[1].split("private func nativeMatches", 1)[0]
        self.assertLess(reload.index("didLoadUniqueInventory()"),
                        reload.index("reconcileFailedPreferenceWrite()"))
        # All unsafe inventory states must discard the compensation plan.
        failure = reload.split("case .reportFailure:", 1)[1].split("case .publish:", 1)[0]
        duplicate = reload.split("case .duplicate:", 1)[1].split("case .none:", 1)[0]
        interrupted = reload.split("if self.preferenceJournal.state != .clear", 1)[1].split("if self.reconcileFailedPreferenceWrite()", 1)[0]
        for invalid in (failure, duplicate, interrupted):
            self.assertIn("self.pendingPreferenceRollback = nil", invalid)
            self.assertIn("return", invalid)
            self.assertNotIn("save(plan.prior)", invalid)

    def test_restore_consumes_plan_and_never_recurses_or_reconnects(self):
        capture = APP.split("private func capturePreferenceRollback", 1)[1].split("private func reconcileFailedPreferenceWrite", 1)[0]
        self.assertIn("!startingPreferenceRollback", capture)
        self.assertIn("prior.routeMode == .split", capture)
        self.assertIn("attempted.routeMode == .split", capture)
        reconcile = APP.split("private func reconcileFailedPreferenceWrite()", 1)[1].split("private func remediateLegacyFullTunnel()", 1)[0]
        self.assertLess(reconcile.index("pendingPreferenceRollback = nil"), reconcile.index("save(plan.prior)"))
        self.assertIn("SharedProfileStore.load() == plan.prior", reconcile)
        self.assertIn("manager.connection.status == .disconnected", reconcile)
        self.assertIn("nativeMatches(manager, plan.attempted)", reconcile)
        self.assertNotIn("connectAfterSave: true", reconcile)
        self.assertIn("native_preference_rollback_smoke.swift", WORKFLOW)

    def test_partial_native_write_cannot_authorize_connect_or_chat(self):
        connect = APP.split("func connect()", 1)[1].split("func disconnect()", 1)[0]
        self.assertLess(connect.index("SharedProfileStore.load() == profile"),
                        connect.index("manager.connection.startVPNTunnel()"))
        self.assertLess(connect.index("nativeMatches(manager, profile)"),
                        connect.index("manager.connection.startVPNTunnel()"))
        chat = APP.split("var canShowPrivateChat: Bool", 1)[1]
        self.assertIn("SharedProfileStore.load() == profile", chat)
        self.assertIn("nativeMatches(manager, profile)", chat)

if __name__ == "__main__":
    unittest.main()
