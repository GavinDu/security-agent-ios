#!/usr/bin/env python3
"""Validate the redacted split-tunnel device report contract, not its truth.

No networking, signing, packet capture or device access is performed here.
The operator supplies observations and hashes of separately redacted evidence.
"""
import argparse
import datetime
import json
from pathlib import Path
import re
import sys

SCHEMA = 1
MAX_BYTES = 64 * 1024
# Every case is mandatory; unavailable environments remain explicitly not_run.
CASES = tuple(
    f"{network}_{check}"
    for network in ("wifi", "cellular")
    for check in (
        "public_ipv4_egress", "public_ipv6_egress", "system_dns",
        "private_route_only", "authenticated_handshake", "private_agent_reachable",
        "no_outer_packetflow",
        "unsafe_inner_a", "unsafe_mixed_answers", "unsafe_mapped_aaaa",
        "empty_answer", "dns_error", "dns_timeout", "stop_preserves_public",
    )
) + (
    "nat64_synthesized_aaaa", "nat64_authenticated_udp",
    "nat64_no_outer_packetflow", "nat64_public_egress_dns",
    "ddns_fresh_restart", "ddns_unsafe_restart", "wifi_to_cellular", "cellular_to_wifi",
    "stale_callback_after_stop", "full_mode_refused",
)
TOP_KEYS = {
    "schema", "app_commit", "ios_version", "device_model",
    "recorded_at_utc", "signed_device", "peer_engine", "peer_version", "cases",
}
ROW_KEYS = {"status", "evidence_sha256"}
STATUSES = {"pass", "fail", "not_run"}


class InvalidReport(ValueError):
    """Messages deliberately contain no operator-provided values."""


def require(condition, message):
    if not condition:
        raise InvalidReport(message)


def matches(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def validate(report):
    require(type(report) is dict and set(report) == TOP_KEYS, "invalid report fields")
    require(type(report["schema"]) is int and report["schema"] == SCHEMA, "invalid schema")
    require(matches(report["app_commit"], r"[0-9a-f]{40}"), "invalid app commit")
    require(matches(report["ios_version"], r"[0-9]{1,2}\.[0-9]{1,2}(\.[0-9]{1,2})?"), "invalid iOS version")
    require(matches(report["device_model"], r"iPhone[0-9]{1,2},[0-9]{1,2}"), "invalid device model")
    require(matches(report["recorded_at_utc"], r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"), "invalid timestamp")
    try:
        datetime.datetime.strptime(report["recorded_at_utc"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise InvalidReport("invalid timestamp") from None
    require(type(report["signed_device"]) is bool, "invalid signed-device attestation")
    require(report["peer_engine"] == "boringtun" and report["peer_version"] == "0.7.1", "invalid reference engine")
    rows = report["cases"]
    require(type(rows) is dict and set(rows) == set(CASES), "missing or unknown acceptance cases")
    counts = dict.fromkeys(sorted(STATUSES), 0)
    for case in CASES:
        row = rows[case]
        require(type(row) is dict and set(row) == ROW_KEYS, "invalid case fields")
        status = row["status"]
        require(isinstance(status, str) and status in STATUSES, "invalid case status")
        digest = row["evidence_sha256"]
        if status == "not_run":
            require(digest is None, "not-run case cannot claim evidence")
        else:
            require(report["signed_device"], "observed case requires signed-device attestation")
            require(matches(digest, r"[0-9a-f]{64}") and digest != "0" * 64,
                    "observed case requires redacted evidence digest")
        counts[status] += 1
    return counts


def template(commit, ios_version, device_model, recorded_at):
    report = {
        "schema": SCHEMA, "app_commit": commit, "ios_version": ios_version,
        "device_model": device_model, "recorded_at_utc": recorded_at,
        "signed_device": False, "peer_engine": "boringtun", "peer_version": "0.7.1",
        "cases": {case: {"status": "not_run", "evidence_sha256": None} for case in CASES},
    }
    validate(report)
    return report


def no_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate JSON key")
        obj[key] = value
    return obj


def load_report(path):
    # Bound bytes before parsing; JSON errors may contain sensitive input.
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES, "report exceeds size limit")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
    except InvalidReport:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise InvalidReport("cannot read valid JSON report") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    new = sub.add_parser("template")
    new.add_argument("--commit", required=True)
    new.add_argument("--ios-version", required=True)
    new.add_argument("--device-model", required=True)
    new.add_argument("--recorded-at", required=True)
    check = sub.add_parser("check")
    check.add_argument("report")
    check.add_argument("--require-complete", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "template":
            print(json.dumps(template(args.commit, args.ios_version, args.device_model, args.recorded_at), indent=2))
            return 0
        counts = validate(load_report(args.report))
        print(f"Format valid: pass={counts['pass']} fail={counts['fail']} not_run={counts['not_run']}. Human review of actual redacted device evidence required.")
        if args.require_complete and counts["pass"] != len(CASES):
            return 1
        return 0
    except InvalidReport as error:
        print(f"Invalid report: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
