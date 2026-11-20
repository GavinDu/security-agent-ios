#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
mkdir -p "$test_root/scripts" "$test_root/Tuist" "$test_root/.github/workflows"

cp "$repo_root/.mise.toml" "$test_root/.mise.toml"
cp "$repo_root/.xcode-version" "$test_root/.xcode-version"
cp "$repo_root/Tuist/Package.swift" "$test_root/Tuist/Package.swift"
cp "$repo_root/Project.swift" "$test_root/Project.swift"
cp "$repo_root/scripts/build-wireguard-go.sh" "$test_root/scripts/build-wireguard-go.sh"
cp "$repo_root/.github/workflows/validate.yml" "$test_root/.github/workflows/validate.yml"

FOUNDATION_ROOT="$test_root" bash "$repo_root/scripts/verify-foundation-pins.sh" >/dev/null
# A mutated source pin must fail closed, not silently fall back to master.
sed 's/2fec12a6e1f6e3460b6ee483aa00ad29cddadab1/0000000000000000000000000000000000000000/' \
  "$repo_root/Tuist/Package.swift" > "$test_root/Tuist/Package.swift"
if FOUNDATION_ROOT="$test_root" bash "$repo_root/scripts/verify-foundation-pins.sh" >/dev/null 2>&1; then
  echo "A mismatched upstream revision passed static pin verification" >&2
  exit 1
fi
echo "Pin consistency and negative-case tests passed."
