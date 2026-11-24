"""Enforce main-thread ownership for native VPN app mutating entry points.

This examines the production Swift code, rather than a toy stand-in. Native
iOS compilation and XCTest are mandatory independent gates in validate.yml.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "ios/AgentApp/VPN/TunnelManager.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class VPNMutationMainQueueBoundaryTests(unittest.TestCase):
    @staticmethod
    def _body(entry: str, next_entry: str) -> str:
        return SOURCE.split(entry, 1)[1].split(next_entry, 1)[0]

    def test_disconnect_marshals_before_native_stop(self):
        body = self._body("func disconnect() {", "func changeRoute(to mode: RouteMode)")
        guard = """if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.disconnect() }
            return
        }"""
        self.assertIn(guard, body)
        self.assertLess(body.index(guard), body.index("manager?.connection.stopVPNTunnel()"))
        self.assertEqual(body.count("manager?.connection.stopVPNTunnel()"), 1)

    def test_route_edit_marshals_before_profile_and_status_reads(self):
        body = self._body("func changeRoute(to mode: RouteMode) {", "func setOnDemand(_ enabled: Bool)")
        guard = """if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.changeRoute(to: mode) }
            return
        }"""
        self.assertIn(guard, body)
        self.assertLess(body.index(guard), body.index("guard var updated = profile"))
        self.assertLess(body.index(guard), body.index("manager?.connection.status"))
        self.assertIn("RouteEditSafetyPolicy.permitsEdit(", body)
        self.assertIn("save(updated)", body)

    def test_on_demand_marshals_before_profile_and_error_state(self):
        body = self._body("func setOnDemand(_ enabled: Bool) {", "var canShowPrivateChat: Bool")
        guard = """if !Thread.isMainThread {
            DispatchQueue.main.async { [weak self] in self?.setOnDemand(enabled) }
            return
        }"""
        self.assertIn(guard, body)
        self.assertLess(body.index(guard), body.index("guard var updated = profile"))
        self.assertLess(body.index(guard), body.index("errorMessage ="))
        self.assertIn("save(updated)", body)

    def test_existing_transaction_entrypoint_main_guards_remain(self):
        save = self._body("func save(_ candidate: ServerProfile", "func connect()")
        connect = self._body("func connect()", "func disconnect()")
        self.assertIn("if !Thread.isMainThread", save)
        self.assertIn("if !Thread.isMainThread", connect)
        self.assertIn("self?.save(candidate, connectAfterSave: connectAfterSave)", save)
        self.assertIn("self?.connect()", connect)

    def test_full_native_gates_and_linux_source_regression_run(self):
        self.assertIn("python3 -m unittest discover -s Tests/build -p 'test_*.py' -v", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("Tuist + macOS companion build", WORKFLOW)
        self.assertIn("swiftc -frontend -parse", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
