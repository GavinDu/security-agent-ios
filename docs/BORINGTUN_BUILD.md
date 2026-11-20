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
header **only on PacketTunnel**. No Go toolchain, WireGuardKitGo,
SwiftPM manifest patch or prebuilt binary is used by iPhone.

## Safety and release gates

Static Linux tests verify pinned hashes, source layout and wrapper
failure behavior; these are not native linkage tests. Native Xcode
Actions must compile iPhoneOS, iOS Simulator and XCTest, and separately
compile AgentMac. Signed device testing requires Apple developer
entitlements and an operational Mac Mini peer. Verify authenticated
handshake, encrypted UDP packets, DNS/IPv6, split/full routes, stop,
roaming, background resume and battery/memory consumption.

BoringTun's upstream 0.7.1 session-liveness report
[#495](https://github.com/cloudflare/boringtun/issues/495) requires
time-based regression tests; don't claim safe rekey behavior from
a five-second smoke test. The BSD-3-Clause copyright notice and
Cargo transitive-license inventory are required before distribution.
Never publish credentials, PSKs, signing keys or raw WireGuard logs.
