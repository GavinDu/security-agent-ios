"""Final resolver input guard before async libc DNS lookup: no scoped/control hosts."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "Shared/AsyncUnderlayDNSResolver.swift").read_text()
LINUX = (ROOT / "Tests/build/async_underlay_dns_smoke.swift").read_text()
NATIVE = (ROOT / "Tests/iOS/AsyncUnderlayDNSResolverTests.swift").read_text()
WORKFLOW = (ROOT / ".github/workflows/validate.yml").read_text()
PROJECT = (ROOT / "Project.swift").read_text()


class DNSHostBoundaryTests(unittest.TestCase):
    def test_validate_actual_resolve_before_reserving_worker(self):
        section = SOURCE.split("func resolve(", 1)[1].split("private final class UnderlayDNSOnce", 1)[0]
        for text in [
            "host.utf8.count <= 253",
            "CharacterSet.controlCharacters.contains($0)",
            "CharacterSet.whitespacesAndNewlines.contains($0)",
            '!host.contains("%")',
            '!host.contains("[")',
            '!host.contains("]")',
        ]:
            self.assertIn(text, section)
        self.assertLess(section.index("CharacterSet.controlCharacters.contains($0)"),
                        section.index("lock.lock()"))
        self.assertLess(section.index("if !cancellation.isCancelled { completion(.failure(.lookupFailed)) }"),
                        section.index("worker.async { [self] in"))

    def test_actual_swift_linux_and_native_xctest_are_required(self):
        for payload in [
            '"fe80::1%en0"', '"[2001:db8::1]"', '"home example.test"',
            '"home\\t.example.test"',
        ]:
            self.assertIn(payload, LINUX)
            self.assertIn(payload, NATIVE)
        self.assertIn("preconditionFailure(\"Unsafe DNS lookup executed\")", LINUX)
        self.assertIn("testUnsafeHostInputNeverInvokesDNSLookup", NATIVE)
        self.assertIn("testUnbracketedNumericIPv6StillAcceptedForLookup", NATIVE)
        self.assertIn("Tests/build/async_underlay_dns_smoke.swift", WORKFLOW)
        self.assertIn("Shared/AsyncUnderlayDNSResolver.swift", WORKFLOW)
        self.assertIn("python3 -m unittest discover -s Tests/build", WORKFLOW)
        self.assertIn("Tuist + iOS device and simulator XCTest", WORKFLOW)
        self.assertIn("Tuist + macOS companion build", WORKFLOW)
        self.assertIn('sources: ["ios/PacketTunnel/**/*.swift", "Shared/**/*.swift"]', PROJECT)


if __name__ == "__main__":
    unittest.main()
