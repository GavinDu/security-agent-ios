#!/usr/bin/env bash
# Offline Xcode/Rust CLI contract test; mocks are NOT a native iPhone build.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/root/Vendor/boringtun/boringtun" "$t/bin" "$t/products" "$t/temp"
touch "$t/root/Vendor/boringtun/boringtun/Cargo.toml"
cat > "$t/bin/rustc" <<'MOCK'
#!/usr/bin/env bash
echo "rustc ${FAKE_RUST_VERSION:-1.90.0} (mock)"
MOCK
cat > "$t/bin/git" <<'MOCK'
#!/usr/bin/env bash
case "$*" in
  *"rev-parse HEAD"*) echo "${FAKE_SHA:-253f7afb2b3df9e952065d10bf2af19913cb176b}" ;;
  *"status --porcelain=v1 --untracked-files=all"*) printf '%s' "${FAKE_GIT_STATUS:-}" ;;
  *) exit 2 ;;
esac
MOCK
cat > "$t/bin/cargo" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" == "build" ]] || exit 2
# Xcode iPhoneOS SDKROOT must be replaced with a valid host MacOSX SDK.
# On modern Xcode, unsetting SDKROOT alone also fails to link -lSystem.
[[ "${SDKROOT:-}" == "${FAKE_MACOS_SDK:-unset}" ]] || {
  echo "Cargo must receive macOS host SDKROOT, not the iPhone SDK" >&2
  exit 2
}
case " $* " in
  *" --locked --target "*) ;;
  *) echo "Missing Cargo lock/target" >&2; exit 2 ;;
esac
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--target" ]]; then triple="$2"; break; fi
  shift
done
test -n "${triple:-}"
mkdir -p "$CARGO_TARGET_DIR/$triple/release"
echo 'mock archive' > "$CARGO_TARGET_DIR/$triple/release/libboringtun.a"
MOCK
cat > "$t/bin/xcrun" <<'MOCK'
#!/usr/bin/env bash
if [[ "$1" == "--sdk" && "$2" == "macosx" && "$3" == "--show-sdk-path" ]]; then
  printf '%s\n' "$FAKE_MACOS_SDK"
elif [[ "$1" == "lipo" && "$2" == "-create" ]]; then
  # In a multi-arch case copy the first input, as the mock only checks syntax.
  [[ "$3" == "-output" ]]
  cp "$5" "$4"
elif [[ "$1" == "lipo" && "$3" == "-verify_arch" ]]; then
  [[ -s "$2" && "${FAKE_MISSING_ARCH:-}" != "$4" ]]
else
  exit 2
fi
MOCK
chmod +x "$t/bin/"*
export PATH="$t/bin:$PATH"
export SRCROOT="$t/root"
export BUILT_PRODUCTS_DIR="$t/products"
export TARGET_TEMP_DIR="$t/temp"
export FAKE_MACOS_SDK="$t/sdk/MacOSX.sdk"
mkdir -p "$FAKE_MACOS_SDK"
for platform in iphoneos iphonesimulator; do
  SDKROOT="/Xcode/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk" \
    PLATFORM_NAME="$platform" ARCHS=arm64 bash "$root/scripts/build-boringtun.sh" >/dev/null
  test -s "$BUILT_PRODUCTS_DIR/BoringTunBridge/libboringtun.a"
done
if PLATFORM_NAME=macosx ARCHS=arm64 bash "$root/scripts/build-boringtun.sh" >/dev/null 2>&1; then echo 'Accepted macOS' >&2; exit 1; fi
if PLATFORM_NAME=iphoneos ARCHS=x86_64 bash "$root/scripts/build-boringtun.sh" >/dev/null 2>&1; then echo 'Accepted device x86_64' >&2; exit 1; fi
if FAKE_RUST_VERSION=1.80.0 PLATFORM_NAME=iphoneos ARCHS=arm64 bash "$root/scripts/build-boringtun.sh" >/dev/null 2>&1; then echo 'Accepted wrong rustc' >&2; exit 1; fi
if FAKE_GIT_STATUS='?? injected.rs' PLATFORM_NAME=iphoneos ARCHS=arm64 bash "$root/scripts/build-boringtun.sh" >/dev/null 2>&1; then echo 'Accepted dirty source' >&2; exit 1; fi
if FAKE_MISSING_ARCH=arm64 PLATFORM_NAME=iphoneos ARCHS=arm64 bash "$root/scripts/build-boringtun.sh" >/dev/null 2>&1; then echo 'Accepted missing ABI' >&2; exit 1; fi
if FAKE_MACOS_SDK="$t/sdk/BadOS.sdk" PLATFORM_NAME=iphoneos ARCHS=arm64 bash "$root/scripts/build-boringtun.sh" >/dev/null 2>&1; then
  echo 'Accepted missing MacOSX host SDK' >&2; exit 1
fi
echo 'Rust wrapper positive/negative mock tests passed'
