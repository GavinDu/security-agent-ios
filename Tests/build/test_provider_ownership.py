"""Guard the actual provider wiring and shared engine/callback ownership."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "ios/PacketTunnel/PacketTunnelProvider.swift").read_text()
MODEL = (ROOT / "Shared/PacketTunnelProviderState.swift").read_text()

class ProviderOwnershipTests(unittest.TestCase):
    def test_provider_serializes_start_stop_and_engine_references(self):
        self.assertIn("private let lifecycleQueue = DispatchQueue(", SRC)
        self.assertGreaterEqual(SRC.count("self.lifecycleQueue.async {"), 2)
        self.assertIn("PacketTunnelProviderOwnership<BoringTunTransport>()", SRC)
        self.assertIn("self.ownership.beginStart(completion)", SRC)
        self.assertIn("self.ownership.installEngine(transport)", SRC)
        self.assertIn("self.ownership.finishStart(for: transport, success: error == nil)", SRC)
        self.assertIn("self.ownership.beginStop(completionHandler)", SRC)
        self.assertIn("self.finishStopWaiters()", SRC)
        self.assertIn("guard engine === transport, lifecycle.finishStart(success: success)", MODEL)
        self.assertIn("stopWaiters.append(completion)", MODEL)
        self.assertNotIn("self?.engine = nil", SRC)

    def test_provider_enforces_one_shot_and_rejects_obsolete_stop_callbacks(self):
        start, stop = SRC.split("override func stopTunnel", 1)
        self.assertIn("PacketTunnelOneShot<Error?>(completionHandler)", start)
        self.assertNotIn("completionHandler(", start)
        self.assertIn("completion.call(nil)", start)
        self.assertIn("completion.call(error)", start)
        callback = stop.split("transport.stop {", 1)[1]
        self.assertLess(callback.index("guard self.ownership.finishStop(for: transport) else { return }"),
                        callback.index("self.finishStopWaiters()"))
        self.assertIn("guard engine === transport, lifecycle.finishStop() else { return false }", MODEL)
        self.assertIn("guard lifecycle.phase == .idle else { return (nil, []) }", MODEL)
        self.assertIn("pendingStart = nil", MODEL)
        self.assertIn("stopWaiters.removeAll()", MODEL)
        drain = stop.split("private func finishStopWaiters()", 1)[1]
        self.assertLess(drain.index("callbacks.start?.call(BoringTunError.stopped)"),
                        drain.index("for completion in callbacks.stops"))

    def test_pure_state_declares_all_four_phases(self):
        self.assertIn("case idle, starting, connected, stopping", MODEL)
        self.assertIn("guard phase == .starting else { return false }", MODEL)
        self.assertIn("guard phase == .stopping else { return false }", MODEL)

if __name__ == "__main__":
    unittest.main()
