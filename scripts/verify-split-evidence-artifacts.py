#!/usr/bin/env python3
"""Verify hashes of separately redacted split-device evidence, not its truth.

Run locally against an operator-reviewed directory. Never upload evidence.
"""
import argparse
import hashlib
import hmac
import importlib.util
import os
from pathlib import Path
import stat
import sys

SPEC = importlib.util.spec_from_file_location(
    "split_report_schema", Path(__file__).with_name("validate-split-device-evidence.py")
)
schema = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(schema)
MAX_ARTIFACT_BYTES = 1024 * 1024


def verify(report, directory):
    counts = schema.validate(report)
    checked = 0
    # Linux/macOS only: fail closed rather than follow symlinks or open FIFOs.
    if not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")):
        raise schema.InvalidReport("safe local file verification is unsupported")
    try:
        root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for case in schema.CASES:
                row = report["cases"][case]
                if row["status"] == "not_run":
                    continue
                # Names come only from the finite schema, never the report.
                fd = os.open(case + ".txt", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=root)
                try:
                    meta = os.fstat(fd)
                    schema.require(stat.S_ISREG(meta.st_mode) and
                                   0 < meta.st_size <= MAX_ARTIFACT_BYTES,
                                   "invalid evidence artifact")
                    digest = hashlib.sha256()
                    total = 0
                    while True:
                        data = os.read(fd, min(65536, MAX_ARTIFACT_BYTES + 1 - total))
                        if not data:
                            break
                        total += len(data)
                        schema.require(total <= MAX_ARTIFACT_BYTES, "oversized evidence artifact")
                        digest.update(data)
                    schema.require(total == meta.st_size, "evidence artifact changed during read")
                    schema.require(hmac.compare_digest(digest.hexdigest(), row["evidence_sha256"]),
                                   "evidence digest mismatch")
                    checked += 1
                finally:
                    os.close(fd)
        finally:
            os.close(root)
    except OSError:
        raise schema.InvalidReport("cannot safely read required evidence artifact") from None
    return counts, checked


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("directory")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args(argv)
    try:
        counts, checked = verify(schema.load_report(args.report), args.directory)
    except schema.InvalidReport as error:
        print(f"Invalid evidence: {error}", file=sys.stderr)
        return 2
    print(f"Digest matches={checked}; pass={counts['pass']} fail={counts['fail']} "
          f"not_run={counts['not_run']}. Human review of redaction, signing and observations required.")
    if args.require_complete and counts["pass"] != len(schema.CASES):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
