#!/usr/bin/env bash
set -euo pipefail
expected_sha="253f7afb2b3df9e952065d10bf2af19913cb176b"
upstream="https://github.com/cloudflare/boringtun.git"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checkout="$root/Vendor/boringtun"
command -v git >/dev/null || { echo "git required" >&2; exit 2; }
mkdir -p "$root/Vendor"
if [[ ! -d "$checkout/.git" ]]; then
  [[ ! -e "$checkout" ]] || { echo "Unexpected vendor directory" >&2; exit 2; }
  stage="$(mktemp -d "$root/Vendor/boringtun.stage.XXXXXX")"
  trap 'rm -rf "$stage"' EXIT
  git -C "$stage" init -q
  git -C "$stage" remote add origin "$upstream"
  git -C "$stage" fetch -q --depth=1 origin "$expected_sha"
  git -C "$stage" checkout -q --detach FETCH_HEAD
  [[ "$(git -C "$stage" rev-parse HEAD)" == "$expected_sha" ]] || exit 2
  mv "$stage" "$checkout"
  trap - EXIT
fi
[[ "$(git -C "$checkout" rev-parse HEAD)" == "$expected_sha" ]] || {
  echo "BoringTun SHA does not match pinned 0.7.1 tag" >&2; exit 2;
}
[[ -z "$(git -C "$checkout" status --porcelain=v1 --untracked-files=all)" ]] || {
  echo "Dirty BoringTun checkout; fail closed" >&2; exit 2;
}
test -f "$checkout/Cargo.lock"
test -f "$checkout/boringtun/src/wireguard_ffi.h"
test -f "$checkout/LICENSE.md"
echo "BoringTun 0.7.1 source verified"
