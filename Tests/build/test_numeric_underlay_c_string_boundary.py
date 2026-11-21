"""Underlay numeric addresses must be bounded before passing C strings to inet_pton."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "Shared/ResolvedUnderlayCandidatePolicy.swift").read_text()
SMOKE = (ROOT / "Tests/build/resolved_underlay_candidate_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/ResolvedUnderlayCandidatePolicyTests.swift").read_text()
WF = (ROOT / ".github/workflows/validate.yml").read_text()

class NumericUnderlayBoundaryTests(unittest.TestCase):
    def test_candidate_count_and_host_bound_precede_c_parser(self):
        self.assertIn("addresses.count <= 32", POLICY)
        self.assertIn("host.utf8.count <= 45", POLICY)
        self.assertIn('host.contains("\\0")', POLICY)
        self.assertLess(POLICY.index("addresses.count <= 32"),
                        POLICY.index("for host in addresses"))
        self.assertLess(POLICY.index('host.contains("\\0")'),
                        POLICY.index("host.withCString"))

    def test_actual_compiled_swift_and_native_xctest(self):
        self.assertIn('count: 32', SMOKE)
        self.assertIn('count: 33', SMOKE)
        self.assertIn('testRejectsOversizedAndNULNumericAnswers', NATIVE)
        self.assertIn('Shared/ResolvedUnderlayCandidatePolicy.swift', WF)
        self.assertIn('Tests/build/resolved_underlay_candidate_smoke.swift', WF)
        self.assertIn("python3 -m unittest discover -s Tests/build", WF)

if __name__ == "__main__":
    unittest.main()
