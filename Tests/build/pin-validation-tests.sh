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
cp "$repo_root/scripts/bootstrap-wireguard.sh" "$test_root/scripts/bootstrap-wireguard.sh"
cp "$repo_root/scripts/patch-wireguard-manifest.py" "$test_root/scripts/patch-wireguard-manifest.py"
cp "$repo_root/.github/workflows/validate.yml" "$test_root/.github/workflows/validate.yml"

FOUNDATION_ROOT="$test_root" bash "$repo_root/scripts/verify-foundation-pins.sh" >/dev/null
# A mutated bootstrap source pin must fail closed.
sed 's/2fec12a6e1f6e3460b6ee483aa00ad29cddadab1/0000000000000000000000000000000000000000/' \
  "$repo_root/scripts/bootstrap-wireguard.sh" > "$test_root/scripts/bootstrap-wireguard.sh"
if FOUNDATION_ROOT="$test_root" bash "$repo_root/scripts/verify-foundation-pins.sh" >/dev/null 2>&1; then
  echo "A mismatched upstream revision passed static pin verification" >&2
  exit 1
fi
cp "$repo_root/scripts/bootstrap-wireguard.sh" "$test_root/scripts/bootstrap-wireguard.sh"
# For the static Go archive, reject a dynamic-framework dependency mapping.
sed 's/\.staticFramework/\.framework/' \
  "$repo_root/Tuist/Package.swift" > "$test_root/Tuist/Package.swift"
if FOUNDATION_ROOT="$test_root" bash "$repo_root/scripts/verify-foundation-pins.sh" >/dev/null 2>&1; then
  echo "Dynamic WireGuardKit framework mapping passed static dependency check" >&2
  exit 1
fi
# Detect a future ubuntu-latest migration that breaks Swift 6.0 installer.
cp "$repo_root/Tuist/Package.swift" "$test_root/Tuist/Package.swift"
sed 's/ubuntu-24\.04/ubuntu-latest/' \
  "$repo_root/.github/workflows/validate.yml" > "$test_root/.github/workflows/validate.yml"
if FOUNDATION_ROOT="$test_root" bash "$repo_root/scripts/verify-foundation-pins.sh" >/dev/null 2>&1; then
  echo "Unpinned Ubuntu runner label passed invariant checks" >&2
  exit 1
fi
echo "Pin consistency and negative-case tests passed."
