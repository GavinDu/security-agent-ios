#!/usr/bin/env python3
"""Audit the pinned WireGuard source tree; repair only its SwiftPM manifest header.

A matching Git HEAD does not imply a clean checkout. In particular, a tampered
Makefile can execute during Xcode's native pre-build even when HEAD is pinned.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

OLD = b"// swift-tools-version:5.3\n"
NEW = b"// swift-tools-version:5.5\n"
ALLOWED_DIRTY_ENTRY = b" M Package.swift"


def fixed_manifest(original: bytes) -> bytes:
    if not original.startswith(OLD):
        raise ValueError("unexpected upstream Package.swift header")
    return NEW + original[len(OLD):]


def verify_worktree(checkout: Path) -> None:
    """Permit only our exact unstaged manifest-header overlay.

    Staged changes, modified tracked Go/Swift/Makefile files, deleted source,
    or untracked nonignored files are all forbidden. The byte-for-byte
    Package.swift check below prevents changing anything beyond its header.
    """
    raw = subprocess.check_output(
        ["git", "-C", str(checkout), "status",
         "--porcelain=v1", "-z", "--untracked-files=all"]
    )
    changes = tuple(record for record in raw.split(b"\0") if record)
    if changes not in ((), (ALLOWED_DIRTY_ENTRY,)):
        # Diagnostic entries are relative paths / two-character Git statuses,
        # never file contents, keys, manifests or environment variables.
        # Bound and escape all output to avoid terminal/control injection.
        preview = [repr(item[:160]) for item in changes[:8]]
        raise ValueError(
            f"unreviewed or untracked WireGuard source modifications "
            f"(count={len(changes)}, entries={preview})"
        )


def apply(checkout: Path, *, check_only: bool = False) -> None:
    verify_worktree(checkout)
    original = subprocess.check_output(
        ["git", "-C", str(checkout), "show", "HEAD:Package.swift"]
    )
    expected = fixed_manifest(original)
    manifest = checkout / "Package.swift"
    current = manifest.read_bytes()
    if check_only:
        if current != expected:
            raise ValueError("WireGuard manifest header overlay is missing")
    else:
        if current not in (original, expected):
            raise ValueError("unexpected vendor Package.swift modifications")
        if current != expected:
            manifest.write_bytes(expected)
    if manifest.read_bytes() != expected:
        raise RuntimeError("patched manifest verification failed")
    verify_worktree(checkout)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3) or (
        len(sys.argv) == 3 and sys.argv[2] != "--check"
    ):
        raise SystemExit("usage: patch-wireguard-manifest.py CHECKOUT [--check]")
    try:
        apply(Path(sys.argv[1]), check_only=len(sys.argv) == 3)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"WireGuard source verification rejected: {exc}")
