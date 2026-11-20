# Deterministic WireGuardKitGo build (Phase 0)

**Status: implementation committed, native CI result pending.** This is not
a signed-iPhone or VPN connectivity certification.

## Toolchain source of truth

- Xcode 16.4 (pinned in `.xcode-version`; selected by GitHub Actions).
- Tuist CLI 4.218.1 and Go 1.19.13 (both pinned in `.mise.toml`).
- WireGuard Apple **exact revision**
  `2fec12a6e1f6e3460b6ee483aa00ad29cddadab1`, specified in
  `Tuist/Package.swift` and checked by the native pre-build script.
- `wireguard-go` uses the upstream `go.mod` + `go.sum` of the
  pinned checkout. Do not replace those with floating module versions.

WireGuardKit's SwiftPM target links `libwg-go.a` but SwiftPM cannot build
that Go archive automatically. The Tuist PacketTunnel target now declares
a **pre-build phase** that runs `scripts/build-wireguard-go.sh` and
searches a deterministic set of package checkout paths. The script rejects
a mismatched upstream commit and incompatible Go version. The PacketTunnel
target sets `LIBRARY_SEARCH_PATHS` and `-lwg-go` to link the resulting
archive. No manual edits to the generated Xcode project are required.

The archive is built **per SDK** in Xcode's build product path; the script
allows `iphoneos` and `iphonesimulator` and rejects unknown architectures.
The upstream Makefile handles iOS `GOOS`; simulator builds pass their
own SDKROOT/target flags. CI must validate this on an actual macOS runner.

## Clean setup on macOS

```bash
# Install mise using your trusted local package manager first.
mise install
tuist install
tuist generate --no-open
# No code signing for CI compilation:
xcodebuild -project SecurityAgent.xcodeproj -scheme AgentApp \
  -configuration Debug -destination 'generic/platform=iOS' \
  CODE_SIGNING_ALLOWED=NO build
xcodebuild -project SecurityAgent.xcodeproj -scheme AgentApp \
  -configuration Debug -destination 'platform=iOS Simulator,name=iPhone 16,OS=latest' \
  CODE_SIGNING_ALLOWED=NO test
xcodebuild -project SecurityAgent.xcodeproj -scheme AgentMac \
  -configuration Debug -destination 'generic/platform=macOS' \
  CODE_SIGNING_ALLOWED=NO build
```

## What still requires the owner

Apple Developer Team ID (`AGENT_APP_TEAM_ID`), real provisioning profiles,
the Packet Tunnel capability and shared App Group provisioned for the signed
bundle IDs. Once CI builds both platforms, sign and install on a **physical
iPhone**, accept iOS VPN permission, and verify a real Mac Mini handshake.
A simulator cannot verify a functioning iOS packet tunnel.

## Failure triage

1. **Checkout not found:** inspect Tuist package resolution paths; never
   substitute a dynamic branch or prebuilt untrusted Go archive.
2. **Go version mismatch:** run `mise install`.
3. **Missing `-lwg-go`:** verify `PacketTunnel` build phase produced
   `$BUILT_PRODUCTS_DIR/WireGuardGoBridge/libwg-go.a` for the current SDK.
4. **Simulator compiler flags:** inspect CI output for specific `GOOS`,
   architecture and SDKROOT failures; update the wrapper for the affected
   architecture, never reuse device archives in simulator binaries.
5. **Entitlements/signing:** CI uses signing disabled; verify an Apple
   Developer provisioning profile separately on a device.

Do not mark #2/#13 complete until CI native build and XCTest are green.

## Licensing

WireGuard Apple's integration is MIT-licensed; Go dependencies retain their
own module licenses. Review the effective dependency inventory before shipping.
Proton Lumo iOS is GPLv3 and used only as a UI/architecture reference — no
Proton source is copied. Do not include any signing material or WireGuard
secrets in the repository or CI artifacts.
