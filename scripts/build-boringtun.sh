#!/usr/bin/env bash
# Build BoringTun staticlib for exactly the Xcode SDK/architectures.
set -euo pipefail
readonly pinned="253f7afb2b3df9e952065d10bf2af19913cb176b"
: "${SRCROOT:?SRCROOT required}"
: "${BUILT_PRODUCTS_DIR:?BUILT_PRODUCTS_DIR required}"
: "${TARGET_TEMP_DIR:?TARGET_TEMP_DIR required}"
case "${PLATFORM_NAME:-}" in
  iphoneos|iphonesimulator) ;;
  *) echo "Unsupported platform ${PLATFORM_NAME:-unset}" >&2; exit 2 ;;
esac
command -v rustc >/dev/null || { echo "Rust required" >&2; exit 2; }
[[ "$(rustc --version)" == "rustc 1.90.0 "* ]] || {
  echo "Rust 1.90.0 required" >&2; exit 2;
}
command -v cargo >/dev/null || { echo "Cargo required" >&2; exit 2; }
checkout="$SRCROOT/Vendor/boringtun"
test -f "$checkout/boringtun/Cargo.toml" || {
  echo "Bootstrap BoringTun before Xcode build" >&2; exit 2;
}
[[ "$(git -C "$checkout" rev-parse HEAD)" == "$pinned" ]] || {
  echo "Wrong BoringTun Git revision" >&2; exit 2;
}
[[ -z "$(git -C "$checkout" status --porcelain=v1 --untracked-files=all)" ]] || {
  echo "Dirty BoringTun source is not allowed" >&2; exit 2;
}
archs="${ARCHS:-}"
[[ -n "$archs" ]] || { echo "Missing ARCHS from Xcode" >&2; exit 2; }
out="$BUILT_PRODUCTS_DIR/BoringTunBridge"
temp="$TARGET_TEMP_DIR/BoringTunBridge-${PLATFORM_NAME}"
mkdir -p "$out" "$temp"
declare -a archives=()
for arch in $archs; do
  case "${PLATFORM_NAME}:$arch" in
    iphoneos:arm64) triple="aarch64-apple-ios" ;;
    iphonesimulator:arm64) triple="aarch64-apple-ios-sim" ;;
    iphonesimulator:x86_64) triple="x86_64-apple-ios" ;;
    *) echo "Unsupported iOS SDK/ABI: ${PLATFORM_NAME}/$arch" >&2; exit 2 ;;
  esac
  export CARGO_TARGET_DIR="$temp/$triple"
  cargo build --manifest-path "$checkout/boringtun/Cargo.toml" \
    --lib --release --no-default-features --features ffi-bindings \
    --locked --target "$triple"
  archive="$CARGO_TARGET_DIR/$triple/release/libboringtun.a"
  test -s "$archive" || { echo "Missing BoringTun staticlib" >&2; exit 2; }
  archives+=("$archive")
done
if [[ "${#archives[@]}" -eq 1 ]]; then
  cp "${archives[0]}" "$out/libboringtun.a"
else
  xcrun lipo -create -output "$out/libboringtun.a" "${archives[@]}"
fi
test -s "$out/libboringtun.a" || { echo "Empty BoringTun archive" >&2; exit 2; }
for arch in $archs; do
  xcrun lipo "$out/libboringtun.a" -verify_arch "$arch" || {
    echo "Archive missing ABI: $arch" >&2; exit 2;
  }
done
echo "BoringTun staticlib ready for ${PLATFORM_NAME}: $archs"
