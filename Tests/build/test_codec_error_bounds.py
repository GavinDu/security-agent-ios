"""Regression guard against unsafe Swift size_t-to-Int FFI conversions.

Real Xcode ABI checks and runtime fuzzing remain issues #53 and #58.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CODEC = (ROOT / "ios/PacketTunnel/BoringTunCodec.swift").read_text()

class FFISizeBoundsTests(unittest.TestCase):
    def test_error_branch_before_any_length_cast(self):
        body = CODEC.split("let response = output.withUnsafeMutableBufferPointer",1)[1].split("    func forceHandshake()",1)[0]
        ordered = ["switch operation", "case 0:", "case 2:", "case 1, 4, 6:",
                   "response.size <= numericCast(output.count)", "Int(response.size)",
                   "Data(output.prefix(count))"]
        positions = [body.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("Int(response.size)", body[:body.index("case 1, 4, 6:")])
        self.assertIn("case 2:\n            throw BoringTunError.engineError", body)
        self.assertIn("response.size > 0", body)

if __name__ == "__main__":
    unittest.main()
