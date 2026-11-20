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

# Observed from a clean Tuist 4.218.1 generation in native Actions 44734716986.
# These files are generated project metadata, never source code or scripts.
# Allow precisely these paths, not entire directories or arbitrary new files.
TUIST_GENERATED_PATHS = frozenset({
    b"Derived/InfoPlists/WireGuardKit-Info.plist",
    b"Derived/InfoPlists/WireGuardKitC-Info.plist",
    b"Derived/InfoPlists/WireGuardKitGo-Info.plist",
    b"WireGuardKit.xcodeproj/project.pbxproj",
    b"WireGuardKit.xcodeproj/project.xcworkspace/contents.xcworkspacedata",
})


def approved_generated_file(checkout: Path, entry: bytes) -> bool:
    if not entry.startswith(b"?? "):
        return False
    relative = entry[3:]
    if relative not in TUIST_GENERATED_PATHS:
        return False
    path = checkout / relative.decode("ascii")
    # Do not follow symlinked generated filenames or their parent directories.
    if not path.is_file() or path.is_symlink():
        return False
    parent = path.parent
    while parent != checkout:
        if parent.is_symlink():
            return False
        parent = parent.parent
    return True


def fixed_manifest(original: bytes) -> bytes:
    if not original.startswith(OLD):
        raise ValueError("unexpected upstream Package.swift header")
    return NEW + original[len(OLD):]


def verify_worktree(checkout: Path) -> None:
    """Permit only our exact unstaged manifest-header overlay.

    Staged changes, modified tracked Go/Swift/Makefile files, deleted source,
    and unexpected untracked files are forbidden. Only five exact, observed
    Tuist-generated project/Info.plist paths are allowed untracked. The
    byte-for-byte Package.swift check prevents other manifest changes.
    """
    raw = subprocess.check_output(
        ["git", "-C", str(checkout), "status",
         "--porcelain=v1", "-z", "--untracked-files=all"]
    )
    changes = tuple(record for record in raw.split(b"\0") if record)
    rejected = [
        entry for entry in changes
        if entry != ALLOWED_DIRTY_ENTRY
        and not approved_generated_file(checkout, entry)
    ]
    if rejected:
        # Diagnostic entries are relative paths / two-character Git statuses,
        # never file contents, keys, manifests or environment variables.
        # Bound and escape all output to avoid terminal/control injection.
        preview = [repr(item[:160]) for item in rejected[:8]]
        raise ValueError(
            f"unreviewed or untracked WireGuard source modifications "
            f"(rejected={len(rejected)}, entries={preview})"
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
