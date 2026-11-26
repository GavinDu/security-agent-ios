"""Production provider must classify typed failures only after ownership checks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DNSDiagnosticBoundaryTests(unittest.TestCase):
    def test_classification_follows_current_transport_guard(self):
        source = (ROOT / "ios/PacketTunnel/PacketTunnelProvider.swift").read_text()
        callback = source.split("transport.start(profile: profile)", 1)[1].split("override func stopTunnel", 1)[0]
        stale, current = callback.split("if let error {", 1)
        self.assertIn("self.ownership.finishStart(for: transport, success: error == nil)", stale)
        model = (ROOT / "Shared/PacketTunnelProviderState.swift").read_text()
        self.assertIn("guard engine === transport, lifecycle.finishStart(success: success)", model)
        self.assertNotIn("SharedDiagnostics.record", stale)
        self.assertIn("error as? UnderlayDNSResolutionError", current)
        self.assertIn("SharedDiagnostics.record(dns.diagnosticEventCode)", current)
        self.assertIn("case .unsafeUnderlayEndpoint = configuration", current)
        self.assertIn('SharedDiagnostics.record("unsafe_underlay_rejected")', current)
        self.assertIn('SharedDiagnostics.record("start_failed")', current)
        self.assertNotIn("localizedDescription", current)
        self.assertNotIn("String(describing: error)", current)


if __name__ == "__main__":
    unittest.main()
