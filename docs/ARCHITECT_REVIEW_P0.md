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
- [Actions #44775007953](https://github.com/GavinDu/security-agent-ios/actions/runs/44775007953)
  passed the Linux static/Cargo inventory job and genuine Mac SwiftUI compile.
  The same run **failed iPhoneOS build**; simulator XCTest did not run.
- [#64](https://github.com/GavinDu/security-agent-ios/issues/64) closed only
  for the normal/build Cargo dependency declaration inventory; distribution
  notices, actual binary link map and final legal review remain #55/#31.

## Blocking principal-level findings

| Finding | Severity | Acceptance gate |
| --- | --- | --- |
| Host macOS SDK versus iPhoneOS cross-build | P0 | #63 and #52: native Xcode Rust host build scripts and iOS archive must link; current patch needs green CI |
| Swift/Rust opaque lifetime and unsafe upstream FFI | P0 | #53/#58: crash/malformed input, race and stop/restart testing on native target |
| Successful UDP open is not a WireGuard handshake | P0 | #54: signed iPhone real-peer authenticated connection |
| Full-route UDP recursion or leaked underlay | P0 | #65/#29: prove server socket routing and fail-safe IPv4/IPv6/DNS |
| Upstream 0.7.1 rekey/data stalls | P0 | #57: sustained bidirectional traffic and roaming |
| Signed extension, App Group and shared Keychain | P0 | #40: owner device and entitlement evidence |
| Required native CI checks on protected main | P0 | #13/#39/#48: no bypass or parser-only release |
| Source/license supply chain | P0 | #55/#31: NOTICE, package inventory and actual artifact review |

## CI failure review

[Run #44755911625](https://github.com/GavinDu/security-agent-ios/actions/runs/44755911625)
revealed macOS-host Cargo build scripts inheriting Xcode's iPhoneOS SDK,
failing `ld: library 'System' not found`. Clearing SDKROOT alone did not
resolve the host SDK requirement. [Run #44773740878](https://github.com/GavinDu/security-agent-ios/actions/runs/44773740878)
reproduced the failure. The wrapper now explicitly chooses the macOS
host SDK with `xcrun --sdk macosx --show-sdk-path` when invoking Cargo
with a separate iOS `--target` triple. This still requires genuine native
Xcode evidence, not just a mocked SDK regression test. #63 remains open.

## Additional review findings

- The existing network-settings code sets both IPv4/IPv6 default routes
  for full tunnel; verify the encrypted UDP underlay cannot recursively
  enter those routes before claiming a functional full tunnel (#65).
- VPN profile metadata currently may persist before system VPN permission
  and load-from-preferences succeed. Atomic save and denial recovery are #15.
- BoringTun's upstream panic hook can terminate the extension; malformed
  packet host tests do not substitute for signed-device stress (#58).
- No main-branch ruleset was visible via GitHub API; branch protection API
  access returned 403. An administrator must verify required checks (#48).
- Reference Proton Lumo only for architecture; no GPL source is included.

**Verdict: NOT APPROVED for merge or release** until all relevant native
and physical-device gates pass. Never claim simulated testing proves signed
NetworkExtension lifecycle, battery behavior or safe VPN routes.
