#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/scripts" "$t/Tuist" "$t/.github/workflows"
for f in .mise.toml .xcode-version rust-toolchain.toml Project.swift; do cp "$root/$f" "$t/$f"; done
cp "$root/scripts/bootstrap-boringtun.sh" "$t/scripts/"
cp "$root/scripts/build-boringtun.sh" "$t/scripts/"
cp "$root/Tuist/Package.swift" "$t/Tuist/"
cp "$root/.github/workflows/validate.yml" "$t/.github/workflows/"
FOUNDATION_ROOT="$t" bash "$root/scripts/verify-foundation-pins.sh" >/dev/null
sed 's/253f7afb2b3df9e952065d10bf2af19913cb176b/0000000000000000000000000000000000000000/' "$root/scripts/bootstrap-boringtun.sh" > "$t/scripts/bootstrap-boringtun.sh"
if FOUNDATION_ROOT="$t" bash "$root/scripts/verify-foundation-pins.sh" >/dev/null 2>&1; then
 echo 'A mutated BoringTun SHA was accepted' >&2; exit 1
fi
cp "$root/scripts/bootstrap-boringtun.sh" "$t/scripts/"
sed 's/channel = "1.90.0"/channel = "stable"/' "$root/rust-toolchain.toml" > "$t/rust-toolchain.toml"
if FOUNDATION_ROOT="$t" bash "$root/scripts/verify-foundation-pins.sh" >/dev/null 2>&1; then
 echo 'An unpinned Rust toolchain was accepted' >&2; exit 1
fi
cp "$root/rust-toolchain.toml" "$t/rust-toolchain.toml"
sed 's/ubuntu-24.04/ubuntu-latest/' "$root/.github/workflows/validate.yml" > "$t/.github/workflows/validate.yml"
if FOUNDATION_ROOT="$t" bash "$root/scripts/verify-foundation-pins.sh" >/dev/null 2>&1; then
 echo 'Unpinned Linux runner accepted' >&2; exit 1
fi
echo 'Rust pin negative tests passed'
