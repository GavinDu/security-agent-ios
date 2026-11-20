#!/usr/bin/env bash
# Unit test the fail-closed build wrapper without Xcode/network/Go compilation.
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/root/Vendor/wireguard-apple/Sources/WireGuardKitGo"
mkdir -p "$tmp/root/scripts" "$tmp/bin" "$tmp/products" "$tmp/temp" "$tmp/Build/Products"
# The build script resolves the verifier via SRCROOT; a mocked Xcode root
# must contain the same verifier as the real generated project.
cp "$repo_root/scripts/patch-wireguard-manifest.py" "$tmp/root/scripts/patch-wireguard-manifest.py"
touch "$tmp/root/Vendor/wireguard-apple/Sources/WireGuardKitGo/Makefile"
printf '// swift-tools-version:5.5\nimport PackageDescription\n' > "$tmp/root/Vendor/wireguard-apple/Package.swift"

cat > "$tmp/bin/go" <<'MOCK'
#!/usr/bin/env bash
echo "go version ${FAKE_GO_VERSION:-go1.19.13} darwin/arm64"
MOCK
cat > "$tmp/bin/git" <<'MOCK'
#!/usr/bin/env bash
case "$*" in
  *"rev-parse HEAD"*) echo "${FAKE_WG_SHA:-2fec12a6e1f6e3460b6ee483aa00ad29cddadab1}" ;;
  *"show HEAD:Package.swift"*) printf '// swift-tools-version:5.3\nimport PackageDescription\n' ;;
  *"status --porcelain=v1 -z --untracked-files=all"*)
    printf '%s\0' "${FAKE_VENDOR_STATUS:- M Package.swift}" ;;
  *) echo "unexpected Git operation" >&2; exit 3 ;;
esac
MOCK
cat > "$tmp/bin/xcrun" <<'MOCK'
#!/usr/bin/env bash
if [[ "$1" == "--sdk" ]]; then
  echo "/mock/sdk/$2"
elif [[ "$1" == "lipo" && "$2" == "-info" ]]; then
  echo "Architectures in fat file: arm64"
elif [[ "$1" == "lipo" && "$3" == "-verify_arch" ]]; then
  [[ -s "$2" ]] && [[ "${FAKE_MISSING_ARCH:-}" != "$4" ]]
else
  exit 2
fi
MOCK
cat > "$tmp/bin/make" <<'MOCK'
#!/usr/bin/env bash
for argument in "$@"; do
  case "$argument" in
    DESTDIR=*) path="${argument#DESTDIR=}" ;;
  esac
done
: "${path:?missing destination}"
mkdir -p "$path"
echo 'mock archive' > "$path/libwg-go.a"
MOCK
chmod +x "$tmp/bin/"*

export PATH="$tmp/bin:$PATH"
export SRCROOT="$tmp/root"
export BUILT_PRODUCTS_DIR="$tmp/products"
export TARGET_TEMP_DIR="$tmp/temp"
export BUILD_DIR="$tmp/Build/Products"
export ARCHS=arm64

for platform in iphoneos iphonesimulator; do
  PLATFORM_NAME="$platform" bash "$repo_root/scripts/build-wireguard-go.sh" >/dev/null
  test -s "$BUILT_PRODUCTS_DIR/WireGuardGoBridge/libwg-go.a"
done
if FAKE_GO_VERSION=go1.20.0 PLATFORM_NAME=iphoneos bash "$repo_root/scripts/build-wireguard-go.sh" >/dev/null 2>&1; then
  echo "Wrong Go version was accepted" >&2; exit 1
fi
if FAKE_WG_SHA=0000000000000000000000000000000000000000 PLATFORM_NAME=iphoneos bash "$repo_root/scripts/build-wireguard-go.sh" >/dev/null 2>&1; then
  echo "Wrong WireGuard revision was accepted" >&2; exit 1
fi
if PLATFORM_NAME=macosx bash "$repo_root/scripts/build-wireguard-go.sh" >/dev/null 2>&1; then
  echo "Unsupported platform was accepted" >&2; exit 1
fi
if ARCHS=armv7 PLATFORM_NAME=iphoneos bash "$repo_root/scripts/build-wireguard-go.sh" >/dev/null 2>&1; then
  echo "Unsupported architecture was accepted" >&2; exit 1
fi
if FAKE_MISSING_ARCH=arm64 PLATFORM_NAME=iphoneos bash "$repo_root/scripts/build-wireguard-go.sh" >/dev/null 2>&1; then
  echo "Archive missing requested CPU slice was accepted" >&2; exit 1
fi
if FAKE_VENDOR_STATUS=" M Sources/WireGuardKitGo/Makefile" PLATFORM_NAME=iphoneos bash "$repo_root/scripts/build-wireguard-go.sh" >/dev/null 2>&1; then
  echo "Tampered vendor Makefile was accepted" >&2; exit 1
fi
if FAKE_VENDOR_STATUS="?? Sources/WireGuardKitGo/injected.go" PLATFORM_NAME=iphoneos bash "$repo_root/scripts/build-wireguard-go.sh" >/dev/null 2>&1; then
  echo "Untracked injected Go source was accepted" >&2; exit 1
fi
echo "Bridge wrapper validation passed (mocked SDK/build tools only)."
