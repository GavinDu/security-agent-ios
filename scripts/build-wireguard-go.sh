#!/usr/bin/env bash
# Builds a per-SDK static Go bridge for WireGuardKit before PacketTunnel links.
# Invoked automatically by the Tuist-managed PacketTunnel pre-build phase.
set -euo pipefail

readonly expected_sha="2fec12a6e1f6e3460b6ee483aa00ad29cddadab1"
: "${SRCROOT:?Xcode SRCROOT is required}"
: "${BUILT_PRODUCTS_DIR:?Xcode BUILT_PRODUCTS_DIR is required}"
: "${TARGET_TEMP_DIR:?Xcode TARGET_TEMP_DIR is required}"

platform="${PLATFORM_NAME:-}"
case "$platform" in
  iphoneos|iphonesimulator) ;;
  *) echo "Unsupported WireGuard Go bridge platform: $platform" >&2; exit 2 ;;
esac

if ! command -v go >/dev/null 2>&1; then
  echo "Go 1.19.13 is required (run mise install)." >&2
  exit 2
fi
go_version="$(go version)"
case "$go_version" in
  *"go1.19.13 "*) ;;
  *) echo "Expected go1.19.13, got $go_version" >&2; exit 2 ;;
esac

# The local checkout is prepared before Tuist resolves the package.
checkout="$SRCROOT/Vendor/wireguard-apple"
if [[ ! -f "$checkout/Sources/WireGuardKitGo/Makefile" ]]; then
  echo "Pinned WireGuard source missing; run scripts/bootstrap-wireguard.sh" >&2
  exit 2
fi
actual_sha="$(git -C "$checkout" rev-parse HEAD)"
if [[ "$actual_sha" != "$expected_sha" ]]; then
  echo "WireGuardKit checkout revision does not match pin (expected $expected_sha)." >&2
  exit 2
fi

sdkroot="$(xcrun --sdk "$platform" --show-sdk-path)"
archs="${ARCHS:-}"
if [[ -z "$archs" ]]; then
  echo "Xcode did not supply ARCHS; refusing to guess a native build architecture." >&2
  exit 2
fi
# Disallow unsupported architectures before sending them to the upstream makefile.
for arch in $archs; do
  case "$arch" in arm64|x86_64) ;; *) echo "Unsupported arch: $arch" >&2; exit 2 ;; esac
done

out="$BUILT_PRODUCTS_DIR/WireGuardGoBridge"
tmp="$TARGET_TEMP_DIR/WireGuardGoBridge-$platform"
mkdir -p "$out" "$tmp"

# The upstream Makefile defines GOOS only for 'iphoneos'. On simulator,
# retain the simulator SDKROOT and deployment/compiler flags supplied by Xcode,
# while mapping GOOS to 'ios' via PLATFORM_NAME=iphoneos.
# SDK-specific output/temporary paths prevent device/simulator cache reuse.
make -C "$checkout/Sources/WireGuardKitGo" build \
  PLATFORM_NAME=iphoneos \
  SDKROOT="$sdkroot" \
  ARCHS="$archs" \
  DESTDIR="$out" \
  BUILDDIR="$tmp" \
  CONFIGURATION_BUILD_DIR="$out" \
  CONFIGURATION_TEMP_DIR="$tmp"

test -s "$out/libwg-go.a" || {
  echo "Missing/empty WireGuard Go static archive" >&2
  exit 2
}
xcrun lipo -info "$out/libwg-go.a"
# lipo -info alone succeeds even if a required slice is absent.
# Refuse to link a simulator/device archive with the wrong requested ABI.
for arch in $archs; do
  if ! xcrun lipo "$out/libwg-go.a" -verify_arch "$arch"; then
    echo "WireGuard Go archive is missing Xcode architecture: $arch" >&2
    exit 2
  fi
done
