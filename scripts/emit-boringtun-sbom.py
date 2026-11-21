#!/usr/bin/env python3
"""Deterministic source-resolution SBOM from an already audited Cargo inventory.

This is NOT an iPhone staticlib link map, bundled license text, legal review,
or evidence that every resolved crate was retained in an app binary.
"""
import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

PIN = "253f7afb2b3df9e952065d10bf2af19913cb176b"
EVIDENCE = "Normal/build Cargo resolution and Cargo.lock only; no dev dependencies or binary link map"
SAFE_NAME = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
SAFE_VERSION = re.compile(r"[0-9][0-9A-Za-z.+_-]{0,63}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SBOMError(ValueError):
    pass


def check_spdx(expression):
    """Reuse the same pinned, fail-closed SPDX grammar as the Cargo inventory."""
    path = Path(__file__).with_name("audit-boringtun-licenses.py")
    spec = importlib.util.spec_from_file_location("boringtun_license_audit", path)
    if spec is None or spec.loader is None:
        raise SBOMError("license validator unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.check_license(expression)
    except (module.InventoryError, TypeError):
        raise SBOMError("unsupported or malformed SPDX expression") from None


def build_bom(inventory):
    if not isinstance(inventory, dict) or inventory.get("schema_version") != 1:
        raise SBOMError("invalid license inventory schema")
    if (inventory.get("target") != "aarch64-apple-ios" or
            inventory.get("features") != ["ffi-bindings"] or
            inventory.get("evidence") != EVIDENCE):
        raise SBOMError("inventory does not describe pinned iOS source resolution")
    packages = inventory.get("packages")
    if (not isinstance(packages, list) or not packages or
            type(inventory.get("package_count")) is not int or
            inventory["package_count"] != len(packages)):
        raise SBOMError("invalid Cargo package inventory/count")

    seen = set()
    components = []
    root_license = None
    for package in packages:
        if not isinstance(package, dict):
            raise SBOMError("malformed package entry")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        relation = package.get("relationship")
        if (not isinstance(name, str) or not SAFE_NAME.fullmatch(name) or
                not isinstance(version, str) or not SAFE_VERSION.fullmatch(version)):
            raise SBOMError("unsafe Cargo package identity")
        identity = (name, version, source)
        if identity in seen:
            raise SBOMError("duplicate resolved Cargo package")
        seen.add(identity)
        license_expression = check_spdx(package.get("license"))
        if source == "pinned-upstream-root":
            if (name != "boringtun" or version != "0.7.1" or
                    relation != "root" or package.get("checksum") is not None or
                    root_license is not None):
                raise SBOMError("unexpected or duplicate pinned BoringTun root")
            root_license = license_expression
        elif source == "crates.io":
            checksum = package.get("checksum")
            if (relation not in ("direct", "transitive-or-build") or
                    not isinstance(checksum, str) or not SHA256.fullmatch(checksum)):
                raise SBOMError("untrusted Cargo registry checksum/relationship")
            components.append({
                "type": "library",
                "bom-ref": f"pkg:cargo/{name}@{version}",
                "name": name,
                "version": version,
                "purl": f"pkg:cargo/{name}@{version}",
                "licenses": [{"expression": license_expression}],
                "hashes": [{"alg": "SHA-256", "content": checksum}],
                "properties": [{"name": "security-agent:source-relationship",
                                "value": relation}],
            })
        else:
            raise SBOMError("unreviewed Cargo source")

    if root_license is None:
        raise SBOMError("missing pinned BoringTun root")
    # Sorting independent of inventory ordering; no timestamps/random serials.
    components.sort(key=lambda x: (x["name"], x["version"], x["bom-ref"]))
    if len({x["bom-ref"] for x in components}) != len(components):
        raise SBOMError("ambiguous component reference")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "name": "boringtun",
                "version": "0.7.1",
                "bom-ref": "pinned-upstream-boringtun-0.7.1",
                "licenses": [{"expression": root_license}],
            },
            "properties": [
                {"name": "security-agent:source-git-sha", "value": PIN},
                {"name": "security-agent:cargo-target", "value": "aarch64-apple-ios"},
                {"name": "security-agent:cargo-features", "value": "ffi-bindings"},
                {"name": "security-agent:evidence-scope",
                 "value": "Cargo.lock normal/build source resolution; NOT final binary objects or complete NOTICE"},
            ],
        },
        "components": components,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
        bom = build_bom(inventory)
        args.output.write_text(
            json.dumps(bom, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, TypeError) as exc:
        print("BoringTun source SBOM FAILED: " + str(exc), file=sys.stderr)
        return 2
    print(f"Public Cargo source-resolution SBOM: {len(bom['components'])} registry crates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
