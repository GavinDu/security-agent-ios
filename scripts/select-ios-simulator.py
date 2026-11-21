#!/usr/bin/env python3
"""Find a real available iPhone simulator for native XCTest, or create one
from an already installed iOS runtime. Never select a build-only placeholder,
skip native tests, or download an unreviewed runtime in CI.
"""
import json
import re
import subprocess
import sys

UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
IOS_RUNTIME = re.compile(r"^com\.apple\.CoreSimulator\.SimRuntime\.iOS-(\d+(?:-\d+)*)$")


class SimulatorSelectionError(RuntimeError):
    pass


def version_key(runtime_id):
    if not isinstance(runtime_id, str):
        return ()
    match = IOS_RUNTIME.fullmatch(runtime_id)
    return tuple(int(part) for part in match.group(1).split("-")) if match else ()


def valid_uuid(value):
    return isinstance(value, str) and UUID.fullmatch(value) is not None


def available(device):
    return (device.get("isAvailable") is True or
            device.get("availability") == "(available)")


def select_existing(payload):
    devices = payload.get("devices")
    if not isinstance(devices, dict):
        raise SimulatorSelectionError("invalid simctl devices JSON")
    candidates = []
    for runtime_id, instances in devices.items():
        version = version_key(runtime_id)
        if not version or not isinstance(instances, list):
            continue
        for device in instances:
            if not isinstance(device, dict):
                continue
            name = device.get("name")
            udid = device.get("udid")
            if (isinstance(name, str) and name.startswith("iPhone") and
                    available(device) and valid_uuid(udid)):
                candidates.append((version, name, udid))
    if not candidates:
        return None
    # The newest installed iOS runtime wins, and ties are reproducible.
    return max(candidates, key=lambda item: (item[0], item[1], item[2]))[2]


def select_runtime(payload):
    runtimes = payload.get("runtimes")
    if not isinstance(runtimes, list):
        raise SimulatorSelectionError("invalid simctl runtimes JSON")
    choices = [r["identifier"] for r in runtimes
               if isinstance(r, dict) and r.get("isAvailable") is True and
               version_key(r.get("identifier"))]
    return max(choices, key=version_key) if choices else None


def select_device_type(payload):
    device_types = payload.get("devicetypes")
    if not isinstance(device_types, list):
        raise SimulatorSelectionError("invalid simctl devicetypes JSON")
    options = [(d.get("name"), d.get("identifier")) for d in device_types
               if isinstance(d, dict) and isinstance(d.get("name"), str) and
               d["name"].startswith("iPhone") and
               isinstance(d.get("identifier"), str) and
               d["identifier"].startswith("com.apple.CoreSimulator.SimDeviceType.iPhone-")]
    if not options:
        return None
    # Prefer Xcode 16's iPhone 16 device type if installed, otherwise an iPhone.
    for name, identifier in options:
        if name == "iPhone 16":
            return identifier
    return sorted(options, reverse=True)[0][1]


def ensure_iphone(invoke=subprocess.check_output):
    def query(kind, *args):
        data = invoke(["xcrun", "simctl", "list", "-j", kind, *args])
        try:
            result = json.loads(data)
        except (TypeError, ValueError) as exc:
            raise SimulatorSelectionError("invalid simctl JSON") from exc
        if not isinstance(result, dict):
            raise SimulatorSelectionError("invalid simctl JSON root")
        return result

    device_list = query("devices", "available")
    selected = select_existing(device_list)
    if selected:
        return selected
    runtime = select_runtime(query("runtimes"))
    device_type = select_device_type(query("devicetypes"))
    if not runtime or not device_type:
        raise SimulatorSelectionError(
            "no available iPhone simulator or installed iOS runtime/device type; "
            "install the correct Xcode iOS simulator runtime on the runner"
        )
    result = invoke(["xcrun", "simctl", "create",
                     "iPhone SecurityAgent CI", device_type, runtime])
    created = result.decode("utf-8").strip() if isinstance(result, bytes) else str(result).strip()
    if not valid_uuid(created):
        raise SimulatorSelectionError("simctl create did not return a valid UDID")
    after = query("devices", "available")
    found = any(
        isinstance(d, dict) and d.get("udid") == created and
        isinstance(d.get("name"), str) and d["name"].startswith("iPhone") and
        available(d)
        for devices in after.get("devices", {}).values() if isinstance(devices, list)
        for d in devices
    )
    if not found:
        raise SimulatorSelectionError("created iPhone simulator was not available")
    return created


def main():
    try:
        print(ensure_iphone())
        return 0
    except (SimulatorSelectionError, subprocess.CalledProcessError, OSError) as exc:
        print("Native iOS XCTest simulator preflight FAILED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
