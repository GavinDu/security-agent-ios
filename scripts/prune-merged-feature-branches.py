#!/usr/bin/env python3
"""Prune only explicitly allowlisted, byte-proven merged GitHub feature refs.

This runs ONLY in the post-success main-branch workflow_run job. Never use a
personal access token, untrusted PR checkout, git push --delete, or force ref
movement. All API token access is confined to this main-only Actions step.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "GavinDu/security-agent-ios"
# Add further branches only in a reviewed PR with exact merge/tree evidence.
CANDIDATES = (
    ("fix/ios-underlay-dns-host-155", 156),
    ("fix/ios-pairing-confirmation-157", 158),
    ("fix/ios-private-webkit-store-159", 160),
    ("fix/verified-branch-cleanup-161", 162),
    ("fix/ios-chat-retry-generation-163", 164),
    ("fix/ios-private-chat-native-binding-165", 166),
    ("fix/ios-public-profile-readback-169", 170),
    ("fix/ios-inner-packet-delivery-167", 168),
    ("fix/ios-startup-watchdog-171", 172),
    ("fix/ios-utun-batch-cardinality-173", 174),
    ("fix/ios-vpn-main-entrypoints-175", 176),
    ("fix/ios-utun-protocol-family-177", 178),
    ("fix/ios-chat-document-path-179", 180),
    ("fix/ios-native-profile-timeout-181", 182),
    ("fix/ios-underlay-dns-cancel-183", 184),
    ("fix/ios-boringtun-pending-drain-189", 190),
    ("fix/ios-dns-error-reasons-185", 187),
    ("fix/ios-utun-read-budget-186", 188),
    ("fix/ios-split-dns-deadline-95", 196),
    ("fix/ios-split-route-contract-95", 197),
    ("test/ios-split-device-evidence-28", 198),
    ("test/split-evidence-artifact-integrity-3", 199),
    ("fix/ios-dns-failure-diagnostics-200", 201),
    ("feat/epic-194-route-stop-transaction", 202),
    ("fix/epic-194-prune-202", 203),
    ("fix/epic-194-safe-preference-compensation", 204),
    ("fix/epic-194-prune-204", 206),
    ("fix/epic-194-interrupted-preference-recovery", 205),
    ("test/epic-194-fake-native-manager", 207),
    ("feature/vpn-lifecycle-diagnostics", 210),
    ("feature/vpn-provider-completion-guard", 212),
    ("feature/vpn-native-permission-tests", 213),
    ("feature/vpn-authenticated-path-recovery", 214),
    ("feature/vpn-provider-lifecycle-harness", 216),
    ("feature/vpn-on-demand-opt-out", 219),
    ("feature/macos-pairing-camera", 220),
)


def _blobs(tree: dict) -> dict[str, str]:
    return {
        item["path"]: item["sha"]
        for item in tree.get("tree", [])
        if item.get("type") == "blob"
        and isinstance(item.get("path"), str)
        and isinstance(item.get("sha"), str)
    }


def safe_to_delete(
    branch: str,
    pull: dict,
    branch_ref: dict,
    main_tree: dict,
    feature_tree: dict,
    changed_files: list[dict],
    open_pulls: list[dict],
) -> bool:
    """Conservative pure policy: no unmerged changes, moved ref or open PR."""
    if branch == "main" or branch not in {name for name, _ in CANDIDATES}:
        return False
    if not isinstance(pull, dict) or pull.get("state") != "closed" or not pull.get("merged_at"):
        return False
    base, head = pull.get("base") or {}, pull.get("head") or {}
    if base.get("ref") != "main" or head.get("ref") != branch:
        return False
    if (head.get("repo") or {}).get("full_name") != REPOSITORY:
        return False
    expected = head.get("sha")
    if not expected or (branch_ref.get("object") or {}).get("sha") != expected:
        return False
    if open_pulls or main_tree.get("truncated") or feature_tree.get("truncated"):
        return False
    # GitHub PR files are fetched with per_page=100. Reject an exactly-full
    # response instead of silently missing a second page.
    if not changed_files or len(changed_files) >= 100:
        return False

    main_blobs, feature_blobs = _blobs(main_tree), _blobs(feature_tree)
    # Never discard any entire branch-only file, even outside the PR file list.
    if not set(feature_blobs).issubset(main_blobs):
        return False
    for changed in changed_files:
        status, filename = changed.get("status"), changed.get("filename")
        if status not in ("added", "modified", "removed", "renamed") or not filename:
            return False
        paths = [filename]
        if status == "renamed":
            previous = changed.get("previous_filename")
            if not previous:
                return False
            paths.append(previous)
        for path in paths:
            # Compare exact Git blob identity (or both absent after removal);
            # ahead/behind counts are meaningless for squash-merged branches.
            if feature_blobs.get(path) != main_blobs.get(path):
                return False
        if status == "removed" and (filename in main_blobs or filename in feature_blobs):
            return False
        if status in ("added", "modified", "renamed") and filename not in feature_blobs:
            return False
    return True


def _request(path: str, token: str, method: str = "GET"):
    request = urllib.request.Request(
        "https://api.github.com" + path,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "User-Agent": "security-agent-ios-reviewed-branch-pruner",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read()
    return json.loads(payload) if payload else None


def _ref(name: str, token: str):
    url = "/repos/" + REPOSITORY + "/git/ref/heads/" + urllib.parse.quote(name, safe="/")
    try:
        return _request(url, token)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def _tree_for_commit(commit_sha: str, token: str) -> dict:
    commit = _request("/repos/" + REPOSITORY + "/git/commits/" + commit_sha, token)
    tree_sha = commit["tree"]["sha"]
    return _request("/repos/" + REPOSITORY + "/git/trees/" + tree_sha + "?recursive=1", token)


def _open_pull_requests(branch: str, token: str) -> list[dict]:
    head = urllib.parse.quote(REPOSITORY.split("/")[0] + ":" + branch, safe="")
    return _request(
        "/repos/" + REPOSITORY + "/pulls?state=open&head=" + head + "&per_page=100", token
    )


def _candidate(branch: str, number: int, main_sha: str, main_tree: dict, token: str) -> bool:
    reference = _ref(branch, token)
    if reference is None:
        print("Already absent: " + branch)
        return False
    pull = _request("/repos/" + REPOSITORY + "/pulls/" + str(number), token)
    # Avoid calling downstream APIs if branch/PR ownership or merge is wrong.
    if not (
        pull.get("state") == "closed"
        and pull.get("merged_at")
        and (pull.get("head") or {}).get("ref") == branch
        and (pull.get("base") or {}).get("ref") == "main"
        and (pull.get("head") or {}).get("sha") == reference.get("object", {}).get("sha")
    ):
        print("Not an unchanged merged PR head: " + branch)
        return False
    feature_tree = _tree_for_commit(reference["object"]["sha"], token)
    files = _request(
        "/repos/" + REPOSITORY + "/pulls/" + str(number) + "/files?per_page=100",
        token,
    )
    open_pulls = _open_pull_requests(branch, token)
    if not safe_to_delete(branch, pull, reference, main_tree, feature_tree, files, open_pulls):
        print("Not proven integrated, preserving: " + branch)
        return False

    # A newer main push or an edited feature branch invalidates the proof.
    latest_main, latest_feature = _ref("main", token), _ref(branch, token)
    if (
        latest_main is None
        or latest_main["object"]["sha"] != main_sha
        or latest_feature is None
        or latest_feature["object"]["sha"] != reference["object"]["sha"]
        or _open_pull_requests(branch, token)
    ):
        print("Refs or PR state changed, preserving: " + branch)
        return False

    path = "/repos/" + REPOSITORY + "/git/refs/heads/" + urllib.parse.quote(branch, safe="/")
    _request(path, token, method="DELETE")
    if _ref(branch, token) is not None:
        raise RuntimeError("Ref deletion did not take effect: " + branch)
    print("Verified deleted merged ref: " + branch + " PR #" + str(number))
    return True


def main() -> int:
    if os.getenv("GITHUB_REPOSITORY") != REPOSITORY:
        print("Refusing to operate outside the reviewed repository")
        return 2
    token = os.getenv("GITHUB_TOKEN")
    expected_main = os.getenv("EXPECTED_MAIN_SHA")
    if not token or not expected_main or len(expected_main) != 40:
        print("Missing scoped Actions token or 40-character tested main SHA")
        return 2
    current = _ref("main", token)
    if current is None or current["object"]["sha"] != expected_main:
        print("No matching successful current main SHA; skip without deletion")
        return 0
    main_tree = _tree_for_commit(expected_main, token)
    deleted = 0
    for branch, number in CANDIDATES:
        try:
            if _candidate(branch, number, expected_main, main_tree, token):
                deleted += 1
        except urllib.error.HTTPError as error:
            print("GitHub REST permission/API error for " + branch + ": HTTP " + str(error.code))
            return 1
    print("Reviewed cleanup complete, deleted=" + str(deleted))
    return 0


if __name__ == "__main__":
    sys.exit(main())
