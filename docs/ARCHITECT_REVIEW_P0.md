# Principal iOS/Swift architecture challenge — active Rust foundation

**Nature of review:** structured critical self-review, **not** an external
independent challenger approval. No signed physical-device test was run.
The full superseded implementation review is retained in Git history.

## Verified boundaries

- SwiftUI app, Mac pairing UI and shared models do not import BoringTun's
  C ABI. PacketTunnel links the pinned Rust staticlib through the upstream
  `wireguard_ffi.h`; no alternate protocol engine is configured.
- Rust 1.90.0, BoringTun 0.7.1 SHA `253f7afb2b3df9e952065d10bf2af19913cb176b`
  and Cargo.lock are pinned. The wrapper rejects dirty source, unknown iOS
  SDKs, missing architecture slices and mismatched Rust versions.
- Linux CI typechecks the Swift codec against the real BoringTun C header
  and exercises host C ABI handshake/malformed UDP inputs.
- [Actions #44781160163](https://github.com/GavinDu/security-agent-ios/actions/runs/44781160163)
  passed Linux static/Cargo inventory and genuine Mac SwiftUI compile.
  The native iPhoneOS job **successfully built** pinned BoringTun
  `libboringtun.a` for arm64, then failed Swift type lookup on
  `NWEndpoint` before final app link or simulator XCTest. Fix #66 is
  committed in 7b91685, with native proof still pending.
- [#64](https://github.com/GavinDu/security-agent-ios/issues/64) closed only
  for the normal/build Cargo dependency declaration inventory; distribution
  notices, actual binary link map and final legal review remain #55/#31.

## Verified native iOS foundation checkpoint — 2026-11-20

[Actions #44807258027](https://github.com/GavinDu/security-agent-ios/actions/runs/44807258027)
on exact commit `18c0565110ed96ced13f82abb6b0b087b64d97f8`
passed **real Xcode 16.4 iPhoneOS AgentApp + PacketTunnel compilation
and link** using pinned Rust BoringTun and **iOS Simulator XCTest:
24 tests, zero failures**. The Linux foundation/C ABI job also passed.
The prior `NWEndpoint` ambiguity is resolved in native Swift compilation.

Independently verified and CLOSED on this evidence: #52 (Rust iPhoneOS +
simulator static build/link), #66 (qualified Network.NWEndpoint),
#67 (native profile transaction tests), #68 (origin policy),
#69 (bounded diagnostics), #70 (IP packet envelopes), #71 (fail-closed
full-route policy), #73 (stale callback epochs), and #74 (provider
start/stop ownership). These closures cover only each issue's atomic
scope. Native macOS companion build was still QUEUED at inspection.
Neither unsigned Xcode success nor simulator unit tests prove that a
signed iPhone VPN extension can authenticate, route or reconnect.

**New atomic remaining work**: latest Epic #11 #75 rejects route-mode
edits until system VPN disconnection is confirmed and native on-demand
is disabled. Legacy #30 still owns real async stop/rollback; signed
upgrade #72 and extension lifecycle #14 remain open.

## Blocking principal-level findings

| Finding | Severity | Acceptance gate |
| --- | --- | --- |
| Native Mac companion and complete required CI | P0 | #13/#39: iPhoneOS build and 24 XCTest passed; Mac job still queued, complete three-check gate outstanding |
| Swift/Rust opaque lifetime and unsafe upstream FFI | P0 | #53/#58: crash/malformed input, race and stop/restart testing on native target |
| Successful UDP open is not a WireGuard handshake | P0 | #54: signed iPhone real-peer authenticated connection |
| Full-route UDP recursion or leaked underlay | P0 | #65/#29: prove server socket routing and fail-safe IPv4/IPv6/DNS |
| Upstream 0.7.1 rekey/data stalls | P0 | #57: sustained bidirectional traffic and roaming |
| Signed extension, App Group and shared Keychain | P0 | #40: owner device and entitlement evidence |
| Required native CI checks on protected main | P0 | #13/#39/#48: no bypass or parser-only release |
| Source/license supply chain | P0 | #55/#31: NOTICE, package inventory and actual artifact review |

## CI resolution and remaining native failures

[Actions #44781160163](https://github.com/GavinDu/security-agent-ios/actions/runs/44781160163)
confirmed the macOS host SDK isolation fix: Xcode's BoringTun Cargo phase
linked macOS host build scripts and produced `iphoneos: arm64`
`libboringtun.a` without the previous `ld: library 'System' not found`.
Atomic issue #63 was closed on this narrowly scoped evidence.

Swift compilation then failed because `Network` and `NetworkExtension`
both declare `NWEndpoint`. Commit
[7b91685](https://github.com/GavinDu/security-agent-ios/commit/7b91685d948e6e43d6be7f263d0be6adcf29479a)
qualified `Network.NWEndpoint`. Subsequent native Actions #44807258027
successfully compiled/linked the app and Rust PacketTunnel and passed 24
simulator XCTest cases; #66 is CLOSED. This still does not establish
signed physical-device VPN operation.

## Additional review findings

- `TunnelRouteSafetyPolicy` (#71) explicitly rejects unverified full
  tunnel in the app before disconnecting and again inside the extension
  before calling `setTunnelNetworkSettings`. Although the network-settings
  implementation retains full default routes for later use, they are not
  reachable while fail-closed. Signed-device underlay and leak proof #65/#29
  remains necessary before lifting the guard.
- VPN profile writes now stage App Group publication until native save/reload
  completes (#67). Permission denial, cross-store failure recovery and
  signed-device proof remain #15; do not infer durable atomicity.
- BoringTun's upstream panic hook can terminate the extension; malformed
  packet host tests do not substitute for signed-device stress (#58).
- App Group diagnostic events are intentionally five fixed codes and no
  free-form messages. Prior code read an unrestricted JSON file; atomic
  [#69](https://github.com/GavinDu/security-agent-ios/issues/69)
  adds a 32 KiB bounded FileHandle read, a 100-event retention cap,
  sanitizing old content on decode, and actual Swift Linux smoke tests.
  Signed extension/App Group behavior and optional export stay open #17.
- No main-branch ruleset was visible via GitHub API; branch protection API
  access returned 403. An administrator must verify required checks (#48).
- Reference Proton Lumo only for architecture; no GPL source is included.

**Verdict: NOT APPROVED for merge or release** until all relevant native
and physical-device gates pass. Never claim simulated testing proves signed
NetworkExtension lifecycle, battery behavior or safe VPN routes.
