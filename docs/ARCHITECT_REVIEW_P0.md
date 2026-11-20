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


## Async native save callback identity guard (#76) — 2026-11-20

`ProfileSaveSequencer` previously guarded delayed native save/reload callbacks
only by phase. A late first-transaction callback could be replayed while a
second transaction was in the same stage and commit the old public profile.
A queue-confined monotonically advancing transaction epoch now gates both
callbacks and is invalidated *before* invoking the user completion, which
may start a new transaction. Native XCTest and real Linux Swift executable
cover both stale save-after-denial and stale reload-after-success, without
modifying the Rust BoringTun engine or exposing secrets. This is #76 under
successor Epic #11, separate from signed iPhone system-preference behavior
#15/#40 and any independent external reviewer sign-off.

## Native preferences load generation challenge (#78) — 2026-11-20

Principal-level **structured Swift/iOS self-review**, not an independent external reviewer approval: a pending `loadAllFromPreferences` callback previously checked only the active save phase, so an older callback could replace a newer native manager after a newer save had completed. The fix uses main-queue-confined load generations, invalidates pending reads before both normal system saves and legacy on-demand writes, rejects old/in-flight callbacks, and reports failed current loads without publishing partial manager results. Native iOS XCTest and Linux-compiled production-policy smoke are required on the exact PR head; physical permission-denial and extension launch remain #15/#40. Rust BoringTun remains unchanged and full tunnel remains fail closed.

**Second-pass principal Swift challenge (#78):** native profile setup in `TunnelManager.save` also runs before the sequencer's own main-queue dispatch. Added an explicit main-queue dispatch at the method boundary so the reload generation and manager mutations share a single executor. A nil `loadAllFromPreferences` collection without an error is treated as a failed read, preserving the last confirmed manager rather than claiming an empty profile set. This is a defensive source-level containment, **not** a signed-device or independent external review approval.


## Shared WireGuard identity first-use race — successor #79 (2026-11-20)

**Principal Swift/iOS adversarial source-review finding:** a read-absent → generate → upsert path in the shared Keychain could replace another process's freshly created private key when `SecItemAdd` returned `errSecDuplicateItem`. App and PacketTunnel must never silently rotate that identity, which would invalidate the previously displayed pairing QR and server peer mapping. The normal first-use path is now insert-only with atomic `SecItemAdd`, and duplicate discovery reads, validates and returns the stored winner; any unreadable, corrupt or missing winner fails closed. Production pure Swift helper tests include concurrent inserts and simulated denial; native iOS XCTest and source assertions cover the same implementation. Existing Keychain sharing, OS signing and real app/extension concurrency require physical iPhone evidence (#40); neither Rust BoringTun FFI nor PSK enrollment is changed. This is a **structured self-review**, not an external independent challenger certification.

## Native VPN/App Group public-profile binding — successor #80 (2026-11-20)

The native preference save/reload and App Group public-profile save are separate system stores, not an atomic transaction (#15). A write failure after successful native preferences could leave a stale App Group peer, endpoint, route mode or on-demand value. **Source-level principal Swift/iOS challenge:** the extension previously used only the App Group profile, with no check against the native NETunnelProviderProtocol. New version-2 metadata stores a SHA-256 digest of sorted-key JSON encoding of the validated `ServerProfile` (public fields only). Both app `connect` and the PacketTunnel `startTunnel` use the same Foundation-only validation policy. **The extension checks version/type/digest before constructing `BoringTunTransport` or initializing Rust FFI and before `setTunnelNetworkSettings`**. Missing or old native metadata fails closed, requiring owner-controlled re-pair/re-save; no silent legacy bypass. The digest is consistency detection, not remote authentication, and does not include a private WireGuard key or PSK.

Required evidence: Linux-executed production policy cases (drift, malformed values, v1 migration), native iOS XCTest for deterministic CryptoKit digest/field sensitivity, Xcode iPhoneOS + simulator link, and native Mac build. Signed iPhone extension entitlement, real user permission-denial, re-pair migration/rollback, app restarts, and true Mac handshake remain #15/#40/#54. This is a structured source self-review, not independent external human/agent approval. Rust Cloudflare BoringTun remains the sole protocol backend.

**Second-pass picky Swift/iOS review of #80:** merely comparing a digest in `providerConfiguration` did not detect an independently modified `NETunnelProviderProtocol.serverAddress` or a wrong extension bundle ID. Both app-side connect and PacketTunnel start now require exact `providerBundleIdentifier` and `serverAddress` agreement **before** BoringTun transport construction. The version-2 canonical hash also pins exactly four public fields through `BoundPublicProfileV2`; adding fields to the broader `ServerProfile` in future does not silently change the digest format. These are source-level safety improvements, not signed-device acceptance.

## Duplicate native VPN managers and initial load races — successor #81

Strict source review found `NETunnelProviderManager.loadAllFromPreferences` returning zero/one/multiple matching profiles was reduced with `.first(where:)`, which silently chose an arbitrary manager on duplicate system profiles. An app action could also create a new manager while the initial asynchronous load had not completed. A production, Foundation-only `NativeVPNManagerInventory` selector now has explicit `.none`, `.one`, `.duplicate` outcomes. `TunnelManager` marks initial inventory as loading, blocks saves/connections while pending or duplicate, clears loading only on the current generation, and does not mutate or delete owner VPN preferences on ambiguity. Users must remove duplicate entries in iOS Settings and reload; active owner-controlled sessions are not automatically stopped. Native XCTest, Linux compiled Swift smoke and source-order tests cover the isolated policy and application integration, but physical iPhone preference load/denial, truly simultaneous app lifecycle and deleted duplicate recovery remain #15/#40. This review is a structured principal Swift/iOS self-challenge, not external approval.


## P0 successor #82 — verify saved native VPN state before App Group publication

Principal Swift/iOS adversarial source review found that `ProfileSaveSequencer` accepted a successful `NETunnelProviderManager.loadFromPreferences` completion without verifying the loaded protocol. A stale native endpoint, wrong PacketTunnel bundle, changed metadata digest, disabled configuration or divergent on-demand state could be published as a successful App Group profile even though the extension's later #80 guard would fail the connection. The new Foundation-only `NativePreferenceCommitVerifier` compares the immutable staged bundle/endpoint/v2 digest/enablement/on-demand rule count against a **post-reload** public snapshot on main; failure is routed through the sequencer's standard error callback **before** `SharedProfileStore.save`. No secret keys/PSKs enter native configuration or diagnostics, and no owner-managed profile is deleted as rollback.

Evidence added: Linux-executed real production Swift policy tests, native XCTest for the same mismatch matrix, integration source-order tests enforcing reload → verification → public commit, and required Actions CI. It is **not** evidence of atomic two-store writes, physical iPhone permission denial, or signed extension real-peer behavior; retain #15/#40/#54. This is structured self-review, not third-party architect approval. Pinned Rust BoringTun remains the only protocol backend.


**Second-pass picky Swift/iOS challenge (#82):** rule count alone was insufficient: a reloaded `NEOnDemandRuleDisconnect` would satisfy a single-rule count, although the app staged `NEOnDemandRuleConnect`. The production snapshot now carries a `onDemandUsesConnectRule` flag from the actual `selected.onDemandRules?.first is NEOnDemandRuleConnect`, and the Foundation-only verifier requires it for on-demand saves in addition to exactly one rule. Linux Swift and iOS XCTest reject a wrong-type single rule. This is still not a signed-device validation of Apple's on-demand authorization or any user-defined rule conditions.


## Native preference inventory read-failure trust gate — successor #83 (2026-11-20)

**Strict principal Swift/iOS source challenge:** #81 handled loading and duplicates but left a fail-open transition: on `loadAllFromPreferences` failure, it cleared `nativeInventoryLoading` while keeping `duplicateNativeManagers` false and possibly retaining a stale native manager. That would re-enable `save` or `connect` even though the system never verified current VPN entries. A stale selection could accidentally duplicate a system profile or connect outdated preferences. The new Foundation-only `NativeVPNInventoryTrust` enforces `unverified → loading → verified/failed/ambiguous`; only `verified` permits saving/connecting. On any current failed load, block writes even if previously verified; discarded #78 obsolete callback cannot mutate trust. Native preference mutations revoke trust up front. Only a successful zero/one inventory read or a fully verified native save/reload **and** App Group public commit (#82) restores trust; legacy on-demand changes invalidate and trigger reload. No preferences or owner-managed profile are silently deleted; VPN settings provide a manual Retry control.

Tests include production Swift Linux trust transitions (permission failure, stale result, duplicates, interrupted write, recovery), native XCTest and static guard checks. This is not a signed-device OS permission denial, automatic two-store repair or independent principal architect review. Keep #15/#40/#54 OPEN pending physical iPhone and Mac peer verification. Rust BoringTun remains unchanged.
