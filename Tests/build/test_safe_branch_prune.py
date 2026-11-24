"""Offline execution tests for main-only, exact-tree merged branch cleanup."""
from copy import deepcopy
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[2]
PRUNER = (ROOT / "scripts/prune-merged-feature-branches.py").read_text()
WORKFLOW = (ROOT / ".github/workflows/prune-proven-merged-branches.yml").read_text()
VALIDATE = (ROOT / ".github/workflows/validate.yml").read_text()
POLICY = runpy.run_path(str(ROOT / "scripts/prune-merged-feature-branches.py"))
eligible = POLICY["safe_to_delete"]
BRANCH = "fix/ios-underlay-dns-host-155"


def setup():
    branch_sha = "a" * 40
    pull = {
        "state": "closed",
        "merged_at": "2026-11-23T03:26:49Z",
        "base": {"ref": "main"},
        "head": {
            "sha": branch_sha,
            "ref": BRANCH,
            "repo": {"full_name": "GavinDu/security-agent-ios"},
        },
    }
    reference = {"object": {"sha": branch_sha}}
    main = {"truncated": False, "tree": [
        {"path": "a.swift", "type": "blob", "sha": "1"},
        {"path": "common.swift", "type": "blob", "sha": "2"},
        {"path": "main-only.swift", "type": "blob", "sha": "3"},
    ]}
    feature = {"truncated": False, "tree": [
        {"path": "a.swift", "type": "blob", "sha": "1"},
        {"path": "common.swift", "type": "blob", "sha": "old-main"},
    ]}
    # Different blobs at unrelated paths are allowed after main advances;
    # only true PR changes must match, and every branch file must exist.
    changed = [{"status": "modified", "filename": "a.swift"}]
    return [BRANCH, pull, reference, main, feature, changed, []]


class SafeBranchPrunePolicyTests(unittest.TestCase):
    def test_squash_merged_branch_safe_even_after_main_has_advanced(self):
        self.assertTrue(eligible(*setup()))

    def test_never_delete_default_or_unlisted_branch(self):
        for name in ["main", "unreviewed/branch", "fix/ios-underlay-dns-host-155/evil"]:
            args = setup()
            args[0] = name
            self.assertFalse(eligible(*args))

    def test_unmerged_or_wrong_repo_or_wrong_base(self):
        for change in (
            lambda a: a[1].update(merged_at=None),
            lambda a: a[1]["head"].update(ref="another-branch"),
            lambda a: a[1]["head"]["repo"].update(full_name="other/security-agent-ios"),
            lambda a: a[1]["base"].update(ref="old"),
        ):
            args = setup()
            change(args)
            self.assertFalse(eligible(*args))

    def test_ref_movement_and_open_pr_block_deletion(self):
        moved = setup()
        moved[2]["object"]["sha"] = "b" * 40
        self.assertFalse(eligible(*moved))
        reused = setup()
        reused[6] = [{"number": 999}]
        self.assertFalse(eligible(*reused))

    def test_missing_branch_file_or_changed_blob_block_deletion(self):
        missing = setup()
        missing[4]["tree"].append({"path": "unique-secret.swift", "type": "blob", "sha": "unique"})
        self.assertFalse(eligible(*missing))
        changed = setup()
        changed[4]["tree"][0]["sha"] = "changed"
        self.assertFalse(eligible(*changed))

    def test_no_incomplete_tree_or_pr_file_pagination(self):
        for tree_index in [3, 4]:
            args = setup()
            args[tree_index]["truncated"] = True
            self.assertFalse(eligible(*args))
        args = setup()
        args[5] = []
        self.assertFalse(eligible(*args))
        args = setup()
        args[5] = [{"status": "modified", "filename": "a.swift"}] * 100
        self.assertFalse(eligible(*args))

    def test_renamed_old_path_must_match_and_be_gone(self):
        args = setup()
        args[5] = [
            {"status": "renamed", "filename": "a.swift", "previous_filename": "old.swift"}
        ]
        self.assertTrue(eligible(*args))
        args[4]["tree"].append({"path": "old.swift", "type": "blob", "sha": "extra"})
        self.assertFalse(eligible(*args))

    def test_deleted_path_must_remain_absent_and_status_known(self):
        args = setup()
        args[5] = [{"status": "removed", "filename": "gone.swift"}]
        self.assertTrue(eligible(*args))
        args[5] = [{"status": "unknown", "filename": "a.swift"}]
        self.assertFalse(eligible(*args))


class SafeBranchPruneWiringTests(unittest.TestCase):
    def test_only_trusted_successful_main_workflow_may_write(self):
        for item in (
            "workflow_run:",
            "Native Xcode Rust WireGuard build and tests",
            "github.event.workflow_run.conclusion == 'success'",
            "github.event.workflow_run.event == 'push'",
            "github.event.workflow_run.head_branch == 'main'",
            "github.event.workflow_run.head_repository.full_name == github.repository",
            "contents: write",
            "pull-requests: read",
            "persist-credentials: false",
            "github.event.workflow_run.head_sha",
            "test_safe_branch_prune.py",
        ):
            self.assertIn(item, WORKFLOW)
        self.assertNotIn("pull_request:", WORKFLOW)
        self.assertNotIn("workflow_dispatch:", WORKFLOW)
        self.assertIn("Native Xcode Rust WireGuard build and tests", VALIDATE)
        self.assertIn("python3 -m unittest discover -s Tests/build", VALIDATE)

    def test_exact_current_sha_and_allowlist_before_delete(self):
        for text in (
            'REPOSITORY = "GavinDu/security-agent-ios"',
            '("fix/ios-underlay-dns-host-155", 156)',
            '("fix/ios-pairing-confirmation-157", 158)',
            '("fix/ios-private-webkit-store-159", 160)',
            '("fix/verified-branch-cleanup-161", 162)',
            '("fix/ios-chat-retry-generation-163", 164)',
            '("fix/ios-private-chat-native-binding-165", 166)',
            '("fix/ios-public-profile-readback-169", 170)',
            '("fix/ios-inner-packet-delivery-167", 168)',
            '("fix/ios-startup-watchdog-171", 172)',
            '("fix/ios-utun-batch-cardinality-173", 174)',
            '("fix/ios-vpn-main-entrypoints-175", 176)',
            '("fix/ios-utun-protocol-family-177", 178)',
            '("fix/ios-chat-document-path-179", 180)',
            'if current is None or current["object"]["sha"] != expected_main:',
            "if not safe_to_delete(",
            'method="DELETE"',
            '_ref(branch, token) is not None',
        ):
            self.assertIn(text, PRUNER)
        self.assertNotIn("subprocess", PRUNER)
        self.assertNotIn("force=True", PRUNER)


if __name__ == "__main__":
    unittest.main()
