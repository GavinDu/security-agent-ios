#!/usr/bin/env bash
# Immutable WireGuard source with a single audited manifest-compatibility overlay.
set -euo pipefail
readonly expected_sha="2fec12a6e1f6e3460b6ee483aa00ad29cddadab1"
readonly upstream="https://github.com/WireGuard/wireguard-apple"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checkout="$root/Vendor/wireguard-apple"
command -v git >/dev/null || { echo "git is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "Python 3 is required" >&2; exit 2; }
mkdir -p "$root/Vendor"
if [[ ! -d "$checkout/.git" ]]; then
  [[ ! -e "$checkout" ]] || { echo "Refusing to overwrite unexpected vendor directory" >&2; exit 2; }
  stage="$(mktemp -d "$root/Vendor/wireguard-apple.stage.XXXXXX")"
  trap 'rm -rf "$stage"' EXIT
  git -C "$stage" init -q
  git -C "$stage" remote add origin "$upstream"
  git -C "$stage" fetch -q --depth=1 origin "$expected_sha"
  git -C "$stage" checkout -q --detach FETCH_HEAD
  actual="$(git -C "$stage" rev-parse HEAD)"
  [[ "$actual" == "$expected_sha" ]] || { echo "Fetched source SHA mismatch" >&2; exit 2; }
  mv "$stage" "$checkout"
  trap - EXIT
fi
actual="$(git -C "$checkout" rev-parse HEAD)"
[[ "$actual" == "$expected_sha" ]] || { echo "Pinned WireGuard checkout SHA mismatch" >&2; exit 2; }
python3 "$root/scripts/patch-wireguard-manifest.py" "$checkout"
test -f "$checkout/Sources/WireGuardKitGo/Makefile"
echo "Pinned WireGuardKit source prepared"
