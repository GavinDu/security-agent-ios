"""Ensure diagnostics cannot regress to unbounded or free-form shared logs."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class DiagnosticsBoundaryTests(unittest.TestCase):
    def test_shared_reader_is_bounded_before_decoding(self):
        source = (ROOT / "Shared/SharedDiagnostics.swift").read_text()
        self.assertIn("FileHandle(forReadingFrom: url)", source)
        self.assertIn("read(upToCount: VPNEventHistory.maxFileBytes + 1)", source)
        self.assertNotIn("Data(contentsOf: url)", source)
        self.assertIn("VPNEventHistory.appending(event, to: readBoundedData())", source)

    def test_never_log_arbitrary_event_messages(self):
        source = (ROOT / "Shared/VPNEventHistory.swift").read_text()
        self.assertIn("allowedCodes.contains(code)", source)
        self.assertIn("decoded.filter { allows($0.event) && allowsTimestamp($0.at) }", source)
        self.assertIn("history.suffix(maxRecords)", source)
        self.assertIn("encoded.count <= maxFileBytes", source)

if __name__ == "__main__":
    unittest.main()
