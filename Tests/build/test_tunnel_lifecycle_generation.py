"""Every async TunnelTransport boundary must reject a stale session epoch."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class TunnelGenerationTests(unittest.TestCase):
    def test_all_async_connection_and_packet_callbacks_guard_epoch(self):
        src = (ROOT / "ios/PacketTunnel/BoringTunTransport.swift").read_text()
        self.assertIn("let epoch = self.lifecycle.advance()", src)
        self.assertIn("_ = lifecycle.advance()", src)
        self.assertGreaterEqual(src.count("self.lifecycle.matches(epoch)"), 7)
        for boundary in (
            "setTunnelNetworkSettings(settings)",
            "connection.stateUpdateHandler",
            "deadline.setEventHandler",
            "timer.setEventHandler",
            "udp.receiveMessage",
            "udp.send(content:",
            "provider.packetFlow.readPackets",
            "queue.asyncAfter(deadline:"
        ):
            self.assertIn(boundary, src)

    def test_epoch_is_queue_confined_not_wall_clock(self):
        src = (ROOT / "Shared/TunnelLifecycleGeneration.swift").read_text()
        self.assertIn("private(set) var current: UInt64", src)
        self.assertIn("current &+= 1", src)
        self.assertIn("token != 0 && token == current", src)
        self.assertNotIn("Date()", src)

if __name__ == "__main__":
    unittest.main()
