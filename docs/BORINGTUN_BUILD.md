# BoringTun Rust integration — Phase 0

## Clean macOS setup

Requirements: Xcode 16.4, Tuist 4.218.1 via mise, and Rust 1.90.0
as pinned in rust-toolchain.toml.

```bash
mise install
rustup toolchain install 1.90.0 --profile minimal
rustup target add --toolchain 1.90.0 aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
bash scripts/setup-project.sh
xcodebuild -project SecurityAgent.xcodeproj -scheme AgentApp \
  -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
xcodebuild -project SecurityAgent.xcodeproj -scheme AgentApp \
  -destination 'platform=iOS Simulator,name=iPhone 16,OS=latest' \
  CODE_SIGNING_ALLOWED=NO -parallel-testing-enabled NO test
```

`scripts/bootstrap-boringtun.sh` fetches immutable Cloudflare tag 0.7.1
commit `253f7afb2b3df9e952065d10bf2af19913cb176b`
into a Git-ignored checkout. It rejects mismatched SHA and dirty source.
`scripts/build-boringtun.sh` runs `cargo build --locked` with
`ffi-bindings` and `--no-default-features` for Xcode's platform and
CPU architecture. The build output is outside the vendor checkout,
under TARGET_TEMP_DIR. It verifies the architecture of
`BUILT_PRODUCTS_DIR/BoringTunBridge/libboringtun.a` before the
PacketTunnel target links the staticlib.

`ios/PacketTunnel/BoringTunBridge.h` uses upstream
`boringtun/src/wireguard_ffi.h` as the *only* ABI declaration.
`Project.swift` installs its header search path and Swift bridging
header **only on PacketTunnel**. The iPhone build uses only the pinned
Rust protocol engine and native Swift system APIs; no prebuilt binary is
checked into this repository.

## Safety and release gates

Static Linux tests verify pinned hashes, source layout and wrapper
failure behavior; these are not native linkage tests. Native Xcode
Actions must compile iPhoneOS, iOS Simulator and XCTest, and separately
compile AgentMac. These unsigned gates passed on main commit
`b4d772ee9ac4babddd779cb3cbef66a717e1a98a`
([Actions #45060469690](https://github.com/GavinDu/security-agent-ios/actions/runs/45060469690)).
Signed device testing still requires Apple developer entitlements and an
operational Mac Mini peer. Verify authenticated handshake, encrypted UDP,
split routes and DNS/IPv6, stop, roaming, background resume and
battery/memory consumption ([#40](https://github.com/GavinDu/security-agent-ios/issues/40),
[#54](https://github.com/GavinDu/security-agent-ios/issues/54)).

**Do not test or advertise full tunnel as enabled:** production
`TunnelRouteSafetyPolicy` rejects `.full` in both the app and the extension.
Default IPv4/IPv6 routes, encrypted-underlay exclusion, NAT64 behavior and a
fail-closed kill switch require separate signed-device Mac/iPhone evidence
([#65](https://github.com/GavinDu/security-agent-ios/issues/65),
[#29](https://github.com/GavinDu/security-agent-ios/issues/29)) before that
guard may be reconsidered. Green CI is not release/route certification.

BoringTun's upstream 0.7.1 session-liveness report
[#495](https://github.com/cloudflare/boringtun/issues/495) requires
time-based regression tests; don't claim safe rekey behavior from
a five-second smoke test. The BSD-3-Clause copyright notice and
Cargo transitive-license inventory are required before distribution.
Never publish credentials, PSKs, signing keys or raw WireGuard logs.

## Xcode host SDK and iPhoneOS target SDK (#63)

Xcode invokes Cargo from an iPhoneOS build environment. Cargo also
links macOS host build scripts and compiles the Rust library for an
explicit `aarch64-apple-ios`, `aarch64-apple-ios-sim` or
`x86_64-apple-ios` target. Host build scripts require the **macOS** SDK.

`scripts/build-boringtun.sh` resolves the macOS SDK with
`xcrun --sdk macosx --show-sdk-path` and sets Cargo's `SDKROOT` to
that path while keeping the target-specific Rust `--target` triple.
Only the subprocess inherits this override, not the Xcode project.

[CI #44755911625](https://github.com/GavinDu/security-agent-ios/actions/runs/44755911625)
and [CI #44773740878](https://github.com/GavinDu/security-agent-ios/actions/runs/44773740878)
reported macOS-host `ld: library 'System' not found`; removing
`SDKROOT` alone was insufficient.
[CI #44781160163](https://github.com/GavinDu/security-agent-ios/actions/runs/44781160163)
subsequently built the pinned iPhoneOS arm64 Rust archive successfully,
so the atomic SDK isolation issue #63 is completed. The separate Swift
`NWEndpoint` ambiguity and final app link/simulator XCTest remain
#66/#52/#13.

## Dependency inventory

[Issue #64](https://github.com/GavinDu/security-agent-ios/issues/64)
independently passed an inventory of resolved normal/build Cargo
dependencies and declared license expressions against Cargo.lock.
This does not replace the binary link-map or distribution NOTICE audit
tracked in #55/#31.
