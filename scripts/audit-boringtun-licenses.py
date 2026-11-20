#!/usr/bin/env python3
"""Conservative, deterministic Cargo resolution license inventory.

This is NOT proof of which objects the linker retained, nor legal approval.
Use with pinned BoringTun 0.7.1, the iOS target and ffi-bindings feature.
"""
import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT_NAME = "boringtun"
ROOT_VERSION = "0.7.1"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
# A new SPDX identifier requires a deliberate review; never silently accept it.
PERMITTED = {
    "MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "0BSD",
    "Zlib", "Unicode-3.0", "Unicode-DFS-2016", "CC0-1.0", "Unlicense",
    "OpenSSL",
}
OPERATORS = {"AND", "OR"}
TOKEN = re.compile(r"\(|\)|[A-Za-z0-9][A-Za-z0-9.+-]*")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class InventoryError(ValueError):
    pass


def check_license(expression):
    if not isinstance(expression, str) or not expression.strip():
        raise InventoryError("missing SPDX license declaration")
    tokens = TOKEN.findall(expression)
    if "".join(tokens) != re.sub(r"\s+", "", expression):
        raise InventoryError("unrecognized SPDX license syntax")
    if not tokens or tokens[0] in OPERATORS or tokens[-1] in OPERATORS:
        raise InventoryError("incomplete SPDX expression")
    def parse_atom(i):
        if i >= len(tokens):
            raise InventoryError("incomplete SPDX expression")
        if tokens[i] == "(":
            i = parse_expr(i + 1)
            if i >= len(tokens) or tokens[i] != ")":
                raise InventoryError("unbalanced SPDX expression")
            return i + 1
        if tokens[i] not in PERMITTED:
            raise InventoryError("unreviewed SPDX identifier: " + tokens[i])
        return i + 1

    def parse_expr(i):
        i = parse_atom(i)
        while i < len(tokens) and tokens[i] in OPERATORS:
            i = parse_atom(i + 1)
        return i

    if parse_expr(0) != len(tokens):
        raise InventoryError("malformed SPDX expression")
    return re.sub(r"\s+", " ", expression).strip()


def inventory(metadata, cargo_lock):
    if metadata.get("version") != 1:
        raise InventoryError("unexpected cargo metadata version")
    resolved = metadata.get("resolve")
    if not isinstance(resolved, dict) or not isinstance(resolved.get("nodes"), list):
        raise InventoryError("missing Cargo resolution graph")
    by_id = {pkg["id"]: pkg for pkg in metadata.get("packages", [])}
    root = resolved.get("root")
    if not root or root not in by_id:
        raise InventoryError("missing workspace root package")
    root_pkg = by_id[root]
    if (root_pkg.get("name"), root_pkg.get("version")) != (ROOT_NAME, ROOT_VERSION):
        raise InventoryError("unexpected BoringTun package version")
    # Cargo metadata for a workspace also resolves sibling programs such as
    # boringtun-cli. They are NOT iOS staticlib dependencies; traverse only
    # the actual boringtun package's reachable dependency graph.
    node_map = {node.get("id"): node for node in resolved["nodes"]}
    if root not in node_map:
        raise InventoryError("root absent from Cargo resolution graph")
    node_ids = set()
    pending = [root]
    while pending:
        current = pending.pop()
        if current in node_ids:
            continue
        if current not in node_map or current not in by_id:
            raise InventoryError("dangling Cargo resolution dependency")
        node_ids.add(current)
        for dependency in node_map[current].get("deps", []):
            pending.append(dependency.get("pkg"))
    lock_index = {}
    for pkg in cargo_lock.get("package", []):
        key = (pkg.get("name"), pkg.get("version"), pkg.get("source"))
        if key in lock_index:
            raise InventoryError("duplicate Cargo.lock package identity")
        lock_index[key] = pkg
    direct = {
        dep.get("pkg")
        for node in resolved["nodes"] if node.get("id") == root
        for dep in node.get("deps", [])
    }
    packages = []
    for pkg_id in sorted(node_ids):
        pkg = by_id[pkg_id]
        name, version, source = pkg.get("name"), pkg.get("version"), pkg.get("source")
        if not isinstance(name, str) or not isinstance(version, str):
            raise InventoryError("invalid package identity")
        if source not in (None, REGISTRY):
            raise InventoryError("unreviewed package source for " + name)
        if source is None and pkg_id != root:
            raise InventoryError("unreviewed local path package: " + name)
        lock_pkg = lock_index.get((name, version, source))
        if lock_pkg is None:
            raise InventoryError("package absent from Cargo.lock: " + name)
        checksum = lock_pkg.get("checksum")
        if source == REGISTRY and (
            not isinstance(checksum, str) or not SHA256.fullmatch(checksum)
        ):
            raise InventoryError("missing or invalid locked checksum: " + name)
        license_id = check_license(pkg.get("license"))
        packages.append({
            "name": name,
            "version": version,
            "source": "crates.io" if source == REGISTRY else "pinned-upstream-root",
            "checksum": checksum if source == REGISTRY else None,
            "license": license_id,
            "relationship": "root" if pkg_id == root else (
                "direct" if pkg_id in direct else "transitive-or-build"
            ),
        })
    packages.sort(key=lambda p: (p["name"], p["version"], p["source"]))
    return {
        "schema_version": 1,
        "target": "aarch64-apple-ios",
        "features": ["ffi-bindings"],
        "evidence": "Cargo metadata resolved graph and Cargo.lock only; not a binary link map",
        "package_count": len(packages),
        "packages": packages,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        meta = json.loads(args.metadata.read_text(encoding="utf-8"))
        lock = tomllib.loads(args.lock.read_text(encoding="utf-8"))
        report = inventory(meta, lock)
        args.output.write_text(
            json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    except (InventoryError, OSError, ValueError, KeyError, TypeError) as exc:
        print("BoringTun license inventory FAILED: " + str(exc), file=sys.stderr)
        return 2
    print("BoringTun Cargo inventory: %d reviewed declarations" % report["package_count"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
