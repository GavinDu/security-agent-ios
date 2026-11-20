"""Guard PacketTunnelProvider serial state and owned transport callbacks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class ProviderOwnershipTests(unittest.TestCase):
    def test_provider_serializes_start_stop_and_engine_references(self):
        src = (ROOT / "ios/PacketTunnel/PacketTunnelProvider.swift").read_text()
        self.assertIn("private let lifecycleQueue = DispatchQueue(", src)
        self.assertIn("self.lifecycleQueue.async {", src)
        self.assertIn("self.engine === transport", src)
        self.assertIn("self.lifecycle.finishStart(success: error == nil)", src)
        self.assertIn("self.lifecycle.beginStop()", src)
        self.assertIn("stopWaiters.append(completionHandler)", src)
        self.assertIn("self.finishStopWaiters()", src)
        self.assertNotIn("self?.engine = nil", src)

    def test_pure_state_declares_all_four_phases(self):
        src = (ROOT / "Shared/PacketTunnelProviderState.swift").read_text()
        self.assertIn("case idle, starting, connected, stopping", src)
        self.assertIn("guard phase == .starting else { return false }", src)
        self.assertIn("guard phase == .stopping else { return false }", src)

if __name__ == "__main__":
    unittest.main()
