"""Raw WireGuard underlay host validation precedes C inet_pton and DNS fallback."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "Shared/TunnelUnderlayPolicy.swift").read_text()
SMOKE = (ROOT / "Tests/build/tunnel_underlay_policy_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/TunnelUnderlayPolicyTests.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()


class RawUnderlayHostBoundaryTests(unittest.TestCase):
    def test_raw_host_guard_precedes_route_and_numeric_fallback(self):
        method = POLICY.split("static func permitsLiteralEndpoint(", 1)[1].split(
            "private static func ipv6LiteralBytes", 1
        )[0]
        self.assertIn("host.utf8.count <= 253", method)
        self.assertIn('!host.contains("\\0")', method)
        self.assertIn('!host.contains("%")', method)
        self.assertIn("CharacterSet.controlCharacters.contains($0)", method)
        self.assertLess(method.index("host.utf8.count <= 253"),
                        method.index("let parsedRoutes"))
        self.assertLess(method.index('!host.contains("\\0")'),
                        method.index('if host.contains(":")'))
        self.assertLess(method.index("CharacterSet.controlCharacters.contains($0)"),
                        method.index("guard looksNumeric else"))

    def test_actual_swift_policy_compiled_and_native_test_present(self):
        self.assertIn('validBoundedHost.utf8.count == 253', SMOKE)
        self.assertIn("Unsafe raw host accepted", SMOKE)
        self.assertIn("testRejectsHostControlBytesPercentAndOverlengthBeforeFallback", NATIVE)
        self.assertIn("Shared/TunnelUnderlayPolicy.swift", WORKFLOW)
        self.assertIn("Tests/build/tunnel_underlay_policy_smoke.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
