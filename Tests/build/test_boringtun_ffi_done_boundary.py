"""Pin Rust BoringTun DONE ABI checks to the production Swift result handler."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CODEC = (ROOT / "ios/PacketTunnel/BoringTunCodec.swift").read_text()
POLICY = (ROOT / "Shared/BoringTunFFIDonePolicy.swift").read_text()
WF = (ROOT / ".github/workflows/validate.yml").read_text()


class BoringTunDoneABITests(unittest.TestCase):
    def test_actual_ffi_dispatch_checks_done_size_before_accepting(self):
        switch = CODEC.split("switch operation {", 1)[1].split(
            "func forceHandshake()", 1
        )[0]
        done = switch.split("case 0:", 1)[1].split("case 2:", 1)[0]
        self.assertIn(
            "guard BoringTunFFIDonePolicy.acceptsDoneSize(response.size) else",
            done,
        )
        self.assertIn("throw BoringTunError.invalidResponse", done)
        self.assertLess(
            done.index("BoringTunFFIDonePolicy.acceptsDoneSize"),
            done.index("return .done"),
        )
        self.assertIn("size == 0", POLICY)

    def test_error_code_stays_unsigned_and_packet_outputs_bounded(self):
        switch = CODEC.split("switch operation {", 1)[1].split(
            "func forceHandshake()", 1
        )[0]
        error = switch.split("case 2:", 1)[1].split("case 1, 4, 6:", 1)[0]
        output = switch.split("case 1, 4, 6:", 1)[1]
        self.assertIn("throw BoringTunError.engineError", error)
        self.assertNotIn("Int(response.size)", error)
        self.assertIn("response.size <= numericCast(output.count)", output)
        self.assertIn("let count = Int(response.size)", output)
        self.assertLess(
            output.index("response.size <= numericCast(output.count)"),
            output.index("let count = Int(response.size)"),
        )

    def test_compiled_linux_swift_and_native_xctest_required(self):
        smoke = (ROOT / "Tests/build/boringtun_ffi_done_smoke.swift").read_text()
        native = (ROOT / "Tests/iOS/BoringTunFFIDonePolicyTests.swift").read_text()
        self.assertIn("Int.max", smoke)
        self.assertIn("Int.max", native)
        self.assertIn("Shared/BoringTunFFIDonePolicy.swift", WF)
        self.assertIn("Tests/build/boringtun_ffi_done_smoke.swift", WF)
        self.assertIn("python3 -m unittest discover -s Tests/build", WF)
        self.assertIn("Tuist + iOS device and simulator XCTest", WF)
        self.assertIn("Tuist + macOS companion build", WF)


if __name__ == "__main__":
    unittest.main()
