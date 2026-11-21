"""VPN diagnostic export is opt-in, bounded, and revalidates untrusted events."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
EXPORT = (ROOT / "Shared/VPNEventExport.swift").read_text()
UI = (ROOT / "ios/AgentApp/VPN/VPNStatusView.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()

class RedactedVPNExportBoundaryTests(unittest.TestCase):
    def test_pure_export_rechecks_allowlist_and_never_emits_raw_record(self):
        self.assertIn("VPNEventHistory.allows($0.event)", EXPORT)
        self.assertIn(".suffix(VPNEventHistory.maxRecords)", EXPORT)
        self.assertIn("ISO8601DateFormatter()", EXPORT)
        self.assertIn("formatter.timeZone = TimeZone(secondsFromGMT: 0)", EXPORT)
        self.assertNotIn("JSONEncoder()", EXPORT)
        self.assertNotIn("uuidString", EXPORT)
        self.assertNotIn("endpoint", EXPORT.lower().split("static func redactedtext", 1)[1])
    def test_ui_exports_only_on_user_share_and_not_on_background(self):
        section = UI.split('Section("Recent VPN events")', 1)[1].split('if let profile = tunnel.profile', 1)[0]
        self.assertIn("let events = SharedDiagnostics.events()", section)
        self.assertIn("ShareLink(item: VPNEventExport.redactedText(from: events))", section)
        self.assertIn("if !events.isEmpty", section)
        self.assertNotIn("URLSession", section)
    def test_compiled_swift_and_native_suite_required(self):
        self.assertIn("Shared/VPNEventExport.swift", WORKFLOW)
        self.assertIn("Tests/build/vpn_event_export_smoke.swift", WORKFLOW)
        self.assertTrue((ROOT / "Tests/iOS/VPNEventExportTests.swift").exists())

if __name__ == "__main__":
    unittest.main()
