# Deterministic WireGuardKitGo build (Phase 0)

**Status: implementation committed, native CI result pending.** This is not
a signed-iPhone or VPN connectivity certification.

## Toolchain source of truth

- Xcode 16.4 (pinned in `.xcode-version`; selected by GitHub Actions).
- Tuist CLI 4.218.1 and Go 1.19.13 (both pinned in `.mise.toml`).
- WireGuard Apple **exact revision**
  `2fec12a6e1f6e3460b6ee483aa00ad29cddadab1`, enforced by
  `scripts/bootstrap-wireguard.sh` and the native bridge build wrapper.
  `Tuist/Package.swift` resolves the audited local checkout.
- `wireguard-go` uses the upstream `go.mod` + `go.sum` of the
  pinned checkout. Do not replace those with floating module versions.

WireGuardKit's SwiftPM target links `libwg-go.a` but SwiftPM cannot build
that Go archive automatically. The Tuist PacketTunnel target now declares
a **pre-build phase** that runs `scripts/build-wireguard-go.sh` and
searches a deterministic set of package checkout paths. The script rejects
a mismatched upstream commit and incompatible Go version. The PacketTunnel
target sets `LIBRARY_SEARCH_PATHS` and `-lwg-go` to link the resulting
archive. No manual edits to the generated Xcode project are required.

### Compatibility overlay (required before Tuist install)

The immutable 2023 upstream WireGuard commit advertises
`// swift-tools-version:5.3` while its `Package.swift` requests
`.macOS(.v12)` and `.iOS(.v15)`, which require a newer
PackageDescription API. Both native jobs failed in
[run 44660852753](https://github.com/GavinDu/security-agent-ios/actions/runs/44660852753)
before compilation. This is tracked by
[issue #42](https://github.com/GavinDu/security-agent-ios/issues/42).

`scripts/bootstrap-wireguard.sh` fetches the exact upstream Git SHA into
`Vendor/wireguard-apple` (git-ignored), then
`scripts/patch-wireguard-manifest.py` verifies the original manifest against
`git show HEAD:Package.swift` and changes **only** the version header from
`5.3` to `5.5`. The patch is idempotent, rejects unrelated changes and
modifies no WireGuard Go or Swift implementation files. A future upstream
revision should remove this overlay only after verified native compatibility.
This source preparation happens **before** Tuist processes the local package.
It is an explicit prerequisite on a clean checkout, not a silent post-generation
Xcode modification.

The archive is built **per SDK** in Xcode's build product path; the script
allows `iphoneos` and `iphonesimulator` and rejects unknown architectures.
The upstream Makefile handles iOS `GOOS`; simulator builds pass their
own SDKROOT/target flags. CI must validate this on an actual macOS runner.

## Clean setup on macOS

```bash
# Install mise using your trusted local package manager first.
mise install
bash scripts/setup-project.sh
# Equivalent explicit preparation:
# bash scripts/bootstrap-wireguard.sh
# tuist install
# tuist generate --no-open
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

1. **Checkout not found:** run `bash scripts/bootstrap-wireguard.sh`.
   It refuses wrong Git SHA or a modified manifest beyond the audited
   compatibility header. Never substitute a moving branch or untrusted
   prebuilt Go archive.
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


## Deterministic wrapper tests

`bash scripts/verify-foundation-pins.sh` validates manifest/script/CI version
alignment. `bash Tests/build/bridge-wrapper-tests.sh` tests failure paths with
mock Go, SDK and Make executables (it does **not** prove real Go compilation).
See [architect review](ARCHITECT_REVIEW_P0.md) for remaining native and
physical-device blockers.

## Static framework linkage and architecture guard

The `WireGuardKit` Tuist SPM product must be a `.staticFramework` so its
undefined Go bridge symbols resolve in the final PacketTunnel link, after
the extension's pre-build phase has produced `libwg-go.a`. A dynamic
`.framework` product can fail before the PacketTunnel target is linked.

The wrapper runs `xcrun lipo -verify_arch` for every Xcode-requested
`ARCHS` slice. `lipo -info` alone cannot enforce compatible archives.
These checks do not replace the macOS native CI job.

### lipo input-order correction

The native iPhoneOS build in Actions #44722408227 reached the Go static
archive guard but failed because our `lipo -verify_arch` arguments were in
the wrong order. Apple `lipo` requires the input archive before
`-verify_arch`. The script and mock were corrected together; the
new test is intentionally sensitive to command order. This change does
**not** certify final device/simulator linking.
