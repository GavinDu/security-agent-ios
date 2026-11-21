"""Fail-closed simulator selection for native XCTest, tested without Xcode."""
import json
import unittest
from pathlib import Path
from importlib.util import module_from_spec, spec_from_file_location

ROOT = Path(__file__).resolve().parents[2]
SPEC = spec_from_file_location("ios_simulator_selector", ROOT / "scripts/select-ios-simulator.py")
mod = module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

R18 = "com.apple.CoreSimulator.SimRuntime.iOS-18-5"
R17 = "com.apple.CoreSimulator.SimRuntime.iOS-17-5"
IPHONE = "com.apple.CoreSimulator.SimDeviceType.iPhone-16"
A = "12345678-1234-1234-1234-123456789abc"
B = "12345678-1234-1234-1234-123456789abd"


def device(name, udid, available=True):
    return {"name": name, "udid": udid, "isAvailable": available}


class IOSSimulatorSelectorTests(unittest.TestCase):
    def test_newest_available_iphone_udid_not_ipad_or_placeholder(self):
        result = mod.select_existing({"devices": {
            R17: [device("iPhone 14", A), device("iPad Pro", B)],
            R18: [device("iPhone 16", B), device("iPhone 16 Pro", "invalid-udid")]
        }})
        self.assertEqual(result, B)
        self.assertIsNone(mod.select_existing({"devices": {R18: [
            device("iPhone 16", "evil$(rm -rf /)"), device("iPad mini", A),
            device("iPhone 16", B, False)
        ]}}))

    def test_create_one_iphone_when_installed_runtime_exists(self):
        calls = []
        def invoke(args):
            calls.append(args)
            if args == ["xcrun", "simctl", "list", "-j", "devices", "available"]:
                active = len([c for c in calls if len(c) > 2 and c[2] == "create"]) > 0
                return json.dumps({"devices": {R18: [device("SecurityAgent CI iPhone", A)] if active else []}}).encode()
            if args == ["xcrun", "simctl", "list", "-j", "runtimes"]:
                return json.dumps({"runtimes": [
                    {"identifier": R17, "isAvailable": True},
                    {"identifier": R18, "isAvailable": True}]}).encode()
            if args == ["xcrun", "simctl", "list", "-j", "devicetypes"]:
                return json.dumps({"devicetypes": [
                    {"name": "iPhone 16", "identifier": IPHONE}]}).encode()
            if args == ["xcrun", "simctl", "create", "SecurityAgent CI iPhone", IPHONE, R18]:
                return (A + "\n").encode()
            self.fail("Unexpected subprocess invocation: " + str(args))
        self.assertEqual(mod.ensure_iphone(invoke), A)
        self.assertEqual(len([c for c in calls if len(c) > 2 and c[2] == "create"]), 1)

    def test_runtime_or_device_type_missing_fails_instead_of_skipping_xctest(self):
        def invoke(args):
            if "devices" in args:
                return json.dumps({"devices": {}}).encode()
            if "runtimes" in args:
                return json.dumps({"runtimes": [{"identifier": R18, "isAvailable": False}]}).encode()
            raise AssertionError("Should not create")
        with self.assertRaises(mod.SimulatorSelectionError):
            mod.ensure_iphone(invoke)

    def test_created_uuid_must_be_real_and_available(self):
        calls = []
        def invoke(args):
            calls.append(args)
            if "devices" in args:
                return json.dumps({"devices": {R18: []}}).encode()
            if "runtimes" in args:
                return json.dumps({"runtimes": [{"identifier": R18, "isAvailable": True}]}).encode()
            if "devicetypes" in args:
                return json.dumps({"devicetypes": [{"name": "iPhone 16", "identifier": IPHONE}]}).encode()
            if "create" in args:
                return (A + "\n").encode()
            self.fail("Unexpected command")
        with self.assertRaisesRegex(mod.SimulatorSelectionError, "not available"):
            mod.ensure_iphone(invoke)
        self.assertEqual(len([c for c in calls if "create" in c]), 1)

    def test_invalid_device_json_and_unsafe_identity_rejected(self):
        with self.assertRaises(mod.SimulatorSelectionError):
            mod.select_existing({"devices": []})
        self.assertFalse(mod.valid_uuid("not-a-uuid"))
        self.assertFalse(mod.valid_uuid(A + ";whoami"))
        self.assertIsNone(mod.select_runtime({"runtimes": [
            {"identifier": R18, "isAvailable": False}]}))

    def test_required_workflow_runs_real_tests_on_selected_udid(self):
        workflow = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("python3 scripts/select-ios-simulator.py", workflow)
        self.assertIn('platform=iOS Simulator,id=$SIMULATOR_UDID', workflow)
        self.assertIn("-parallel-testing-enabled NO CODE_SIGNING_ALLOWED=NO test", workflow)
        self.assertNotIn("platform=iOS Simulator,name=iPhone 16,OS=latest", workflow)


if __name__ == "__main__":
    unittest.main()
