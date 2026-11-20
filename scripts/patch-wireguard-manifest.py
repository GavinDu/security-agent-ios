#!/usr/bin/env python3
"""Repair only a proven SwiftPM tools-version mismatch in pinned WireGuard."""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

OLD = b"// swift-tools-version:5.3\n"
NEW = b"// swift-tools-version:5.5\n"

def fixed_manifest(original: bytes) -> bytes:
    if not original.startswith(OLD):
        raise ValueError("unexpected upstream Package.swift header")
    return NEW + original[len(OLD):]

def apply(checkout: Path) -> None:
    original = subprocess.check_output(["git", "-C", str(checkout), "show", "HEAD:Package.swift"])
    expected = fixed_manifest(original)
    path = checkout / "Package.swift"
    current = path.read_bytes()
    if current not in (original, expected):
        raise ValueError("unexpected vendor Package.swift modifications")
    if current != expected:
        path.write_bytes(expected)
    if path.read_bytes() != expected:
        raise RuntimeError("patched manifest verification failed")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch-wireguard-manifest.py CHECKOUT")
    try:
        apply(Path(sys.argv[1]))
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"Manifest patch rejected: {exc}")
