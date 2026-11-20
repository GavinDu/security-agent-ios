# Principal iOS/Swift architect challenge — Epic #6

**Type of review:** Structured principal-architect critique performed in this
implementation session. **No separate external reviewer or signed device test**
has been invoked. Findings below are unverified until CI or device evidence
is linked in their issues.

## Checked against: Tuist manifest / SwiftPM / Network Extension / build safety

| Finding | Severity | Evidence and required follow-up |
| --- | --- | --- |
| A floating WireGuard dependency cannot reproduce archived Go outputs | P0, mitigated in source | `Tuist/Package.swift` pins 2fec12a; build script compares checkout Git SHA |
| Go library must exist for each SDK before PacketTunnel link | P0, pending runtime | Target pre-build script + library path now specified; run native Xcode build in #2 |
| Simulator and device archive ABI differ | P0, pending runtime | Build separately using current SDKROOT, ARCHS and temp folders; verify #37 |
| SwiftPM's package checkout may be stored outside the known paths | P0, pending runtime | Script fails closed rather than fetching master; #38 investigates real Tuist location |
| Go 1.19 source and runtime patch may not compile with Xcode 16.4 | P0, pending runtime | macOS CI #13 must prove compatibility or update pins together in #12 |
| Raw xcodebuild logs must not be published with secrets | P0, mitigated for CI | CI builds with signing disabled and uploads only nonsecret summary; no signing keys committed |
| Legacy parser-only CI is not sufficient | P0, mitigated in workflow | Native build + simulator XCTest + Mac target added; only close #13 when green |
| Real extension entitlement, signing and lifecycle aren't simulated | P0, open | Signed device checkpoint #39; never infer from simulator test |
| Proton Lumo license must remain isolated | P0, documented | Independent project; no GPL-3 source imported; transitive Go licenses need audit (#12/#31) |

## Design decision

Use the upstream WireGuardKit source pinned to an immutable commit and build
the corresponding Go bridge *locally* as an Xcode target pre-build phase.
Do not check in prebuilt .a files or silently download unknown native binaries.
The static `-lwg-go` linker flag and library search path are checked into
Tuist, not manually added in Xcode. Fail early on unsupported SDK/architecture,
tool version or checkout SHA.

**Principal-architect acceptance status:** conditional / NOT approved for
merge. Requires a green device-SDK compile/link, simulator XCTest, macOS
companion compile and signing/real iPhone evidence for Epic #6. Resolve
specific CI failures instead of bypassing native jobs.

## Follow-up challenge — static-vs-dynamic linkage and ABI validation

Review date: 2026-11-19. **Not an independent external reviewer.**

- **Blocker addressed in source:** `PackageSettings` incorrectly declared
  `WireGuardKit: .framework` (dynamic). Its own target would resolve linked
  `wg-go` symbols before the app extension's Go pre-build. Tuist's
  `PackageSettings` defaults to `.staticFramework`, verified against the
  upstream ProjectDescription source. Changed mapping to `.staticFramework`,
  keeping the final `libwg-go.a` linker input in PacketTunnel.
- **Blocker addressed in source:** `lipo -info` does not prove the archive
  contains every architecture Xcode requested. Added `-verify_arch` for
  each `ARCHS` slice, with a negative mock test for missing architecture.
- **Verification isolation:** moved syntax/plist/wrapper tests to Linux,
  leaving macOS Xcode for native build proof. A passing static workflow is not
  evidence of native linker correctness.

**Acceptance:** Static manifest/test review may pass independently.
Keep #2/#12/#13/#36–#40 open until actual matching native CI/device evidence
exists. The macOS runner remains the deciding compile/link gate.

## CI independence and traffic review

- Previous workflow started both `push` and `pull_request` jobs for the
  same feature-branch commit, wasting runner capacity and cancelling queued
  superseded work. Feature branches with PRs now use `pull_request`; only
  `main` uses `push`. `workflow_dispatch` remains available.
- iOS device/simulator builds and macOS companion compilation are now
  independent native CI jobs. An iOS bridge failure must not hide a working
  (or separately broken) macOS companion.
- Any CI failure still fails its own required job. Do not set
  `continue-on-error`, skip a failing platform, or merge without evidence.

## CI failure: setup-swift v2 and Ubuntu 26.04 (confirmed)

Run [44660675965](https://github.com/GavinDu/security-agent-ios/actions/runs/44660675965)
failed in `Foundation static checks (Linux)` before Swift/source execution.
The runner used Ubuntu 26.04.1; `swift-actions/setup-swift@v2` reported:
`Version "26.04" of Ubuntu is not supported`.

**Correction:** Pin the static job to `ubuntu-24.04`, a supported platform
for `setup-swift@v2` and the selected Swift parser. Add a static pin
invariant and a negative runner-migration test. Do not mark #35/#39
complete until the corrected workflow passes.


## 2026-11-20: Concrete native CI failure and corrective design

The latest completed native jobs from [Actions #44660852753](https://github.com/GavinDu/security-agent-ios/actions/runs/44660852753)
both fail at `tuist install`: the pinned WireGuard Apple
`Package.swift` declares tools 5.3 while using `.macOS(.v12)` and
`.iOS(.v15)` APIs introduced with PackageDescription 5.5.

**Principal iOS review finding (P0):** The original remote SwiftPM dependency
cannot be used unchanged with the pinned toolchain. Floating `master`,
copying unreviewed WireGuard code, disabling native CI, or globally editing
SwiftPM caches would be unacceptable.

**Corrective design:** A local `.package(path:)` WireGuard source prepared by
`scripts/bootstrap-wireguard.sh`. It fetches an immutable upstream Git SHA,
compares HEAD, and invokes a small audited Python patcher to modify **only**
the tools-version header after comparing the entire upstream manifest to
the Git object. The local vendor checkout is ignored in the app repository,
and both CI platforms run bootstrap before Tuist resolution.

**Challenge / remaining risks:**
- A clean checkout requires `bash scripts/setup-project.sh` (or an explicit
  bootstrap) before `tuist install`. This deviates from the literal
  two-command installation and is tracked in #42; native CI must establish
  whether the local package integration is supported by Tuist 4.218.1.
- The Go backend is still from 2023 and may fail with modern Apple SDK,
  architecture or runtime patches; keep #2/#12/#36/#37 open until proven.
- Source revision provenance is pinned; transitive module licensing and
  active upstream security support still require audit.
- A green static job is not native build evidence, and a native simulator
  test is not a signed iPhone VPN test.

**Disposition:** source fix proposed and pushed, not independently approved
by a human reviewer and not accepted until native CI verifies it.

## 2026-11-20 — New native iOS failure: lipo argument order

Actions [#44722408227](https://github.com/GavinDu/security-agent-ios/actions/runs/44722408227)
passed foundation static checks and progressed through `tuist install` and
the Go bridge build, exposing an error in our archive architecture guard:

```
lipo: unknown architecture specification flag: .../libwg-go.a
in specifying -verify_arch operation
```

**Principal review:** `lipo` requires its input archive *before*
`-verify_arch`. The previously mocked CLI accepted the inverse,
so the mock test was too permissive. Corrected the invocation to
`xcrun lipo "$archive" -verify_arch "$arch"`, and changed the fixture to
reject wrong argument ordering and missing archive files. Native compile
and link remain unverified until the corrected Actions run passes.


## 2026-11-20 — Reviewer challenge: pinned Git HEAD is not source integrity

**Finding (P0):** An exact checkout SHA alone did not prevent locally modified
`Sources/WireGuardKitGo/Makefile` or injected Go files from executing in the
Xcode pre-build phase. The initial manifest overlay validated only
`Package.swift`; this was a supply-chain verification gap.

**Correction (#44):** `scripts/patch-wireguard-manifest.py` now checks Git
porcelain worktree status before and after applying the overlay, rejecting
staged source edits, dirty tracked implementation files, deleted files and
untracked nonignored files. Exactly one unstaged `Package.swift` change is
allowed, and its bytes must match the immutable upstream Git blob except
for the vetted tools-version header. The native Go build re-checks this
immediately before invoking the upstream Makefile. Python Git-fixture and
mock build-wrapper negative tests cover altered Makefile, staged manifest,
injected untracked Go source and missing overlay.

This is a strict self-review and testable design change, **not** an independent
external challenger or proof of complete upstream/transitive supply-chain
security. Full native build and physical device gates remain open.

## Mock-fixture review correction

Actions [#44725096544](https://github.com/GavinDu/security-agent-ios/actions/runs/44725096544)
passed all five Python integrity tests and static pins but failed the shell
bridge wrapper fixture. The wrapper constructs a temporary fake Xcode source
root without copying the newly required manifest verifier, causing Python
file-not-found. This does not indicate a bypass in production source integrity;
the fixture now copies the verifier into its synthetic `SRCROOT`. Keep issue
#44 open until the corrected static run proves the entire fixture passes.

## 2026-11-20 — Tuist/source guard diagnostic (issue #47)

[Run 44725384814](https://github.com/GavinDu/security-agent-ios/actions/runs/44725384814)
finished with Linux static checks and native Mac build green but iOS app-extension
pre-build failed with `unreviewed or untracked WireGuard source modifications`.
The message lacked path evidence; the integrity guard is **not** disabled.
The source verifier now emits up to eight bounded, escaped Git porcelain *status
records only* (not file contents) on failure, allowing classification of
Tuist/SwiftPM-generated metadata versus a potentially malicious source edit.
An offline test confirms the diagnostic never includes file contents. Await
CI evidence before implementing a narrow metadata allowlist. No native iOS
acceptance is claimed.

## 2026-11-20 — Why is Go included in an iPhone app?

See [ADR-0001](ADR-0001-IOS-VPN-BACKEND.md). Strict architect review
confirmed that Apple NetworkExtension handles VPN integration but does not
supply the WireGuard protocol engine. For an integrated, first-party
WireGuard switch, keep the official Go backend **only as the static native
PacketTunnel extension dependency**; SwiftUI/Keychain/WebKit and the Mac
companion remain Swift. Removing the backend requires switching to an
external VPN product, Apple's IKEv2 protocol/server, or a different audited
userspace engine such as Rust BoringTun. No custom Swift cryptography.

CI on [run 44734716986](https://github.com/GavinDu/security-agent-ios/actions/runs/44734716986)
identified exactly five Tuist-generated metadata files in the local
WireGuard checkout and no source changes. A targeted five-file allowlist
replaces the overstrict rejection; injected Go/Makefiles remain forbidden.
Neither that diagnosis nor the ADR is physical-device verification.

## Nov 20 Rust migration — scope and remaining high-priority findings

Historical Go review entries above apply to earlier commits only. User
explicitly selected BoringTun Rust: see ADR-0002 and #51–#58.

- **P0 FFI:** Upstream `ffi/mod.rs` has unsafe pointer operations and a
  panic hook that raises SIGSEGV. The Swift codec uses an opaque pointer,
  bounded 65,600-byte output buffer and serial queue, but this needs
  native Xcode layout/typechecking and signed-device race tests (#53/#58).
- **P0 handshakes:** UDP socket readiness is not authentication. The new
  Swift extension waits for BoringTun handshake stats and enforces a 15s
  timeout before completing startup (#54).
- **P0 liveness:** Upstream BoringTun 0.7.1 issue #495 reports one-way
  traffic stalls; test rekey, sustained bidirectional traffic and roaming
  against a real Mac peer before release (#57).
- **P0 routing:** Split and full IPv4/IPv6 and DNS are configured in Swift,
  but Mac NAT and physical route exclusion must be checked on an iPhone.
- **P0 build:** Rust source is pinned to commit 253f7afb, with Cargo.lock;
  device/simulator static archives and C imports must compile in Xcode.
- **P0 supplies:** Complete BSD-3-Clause and transitive Cargo notices/SBOM
  and required GitHub branch checks before merging (#55/#48).

**Challenger verdict:** conditional / NOT approved for merge. This is a
structured principal iOS/Swift self-audit, not an independent reviewer.

## 2026-11-20 — P0 Rust host/target cross-compilation review (#63)

Full native [CI run 44755911625](https://github.com/GavinDu/security-agent-ios/actions/runs/44755911625)
completed Linux Rust host FFI checks and an unsigned Mac app build, but
iPhoneOS failed during Cargo host `build.rs` linking with
`ld: library 'System' not found` for `aarch64-apple-darwin`.
The cause is inherited Xcode iPhoneOS `SDKROOT` during cross-compilation.
Use `env -u SDKROOT` **only around Cargo** while retaining the iOS Rust
`--target` triple and all source/archive checks. Do not turn off native CI
or substitute Go. A mocked Xcode SDKROOT test guards against recurrence.
Cross-compile and simulator/link acceptance stay #52/#55 until a real Xcode
run proves them; #63 is assigned to latest Epic #11, not current #6.

## 2026-11-20 — Latest epic #11 independent supply-chain challenge (#64)

**Principal Swift/iOS + Rust supply-chain self-review; no external independent
reviewer.** Cargo.lock pins registry artifacts by checksums, but an immutable
Git checkout alone does **not** enumerate transitive license obligations.
Issue #64 adds a fail-closed inventory driven by Cargo's resolved target graph
and Cargo.lock, with offline adversarial tests and a secret-free CI artifact.
The SPDX allowlist is an audit trigger, **not** a legal opinion or proof of
which code the iOS linker retains. Review the actual BoringTun archive,
transitive notices, licenses and static linkage before beta distribution
(#55/#31). Mark #64 complete only if its new Linux workflow step is green;
native device compilation, signed iPhone routing and FFI stress stay separate
open gates, even if the license inventory passes.

## 2026-11-20 — Strict challenge: host macOS SDK still absent (#63)

Native Actions [#44773740878](https://github.com/GavinDu/security-agent-ios/actions/runs/44773740878)
progressed past Tuist into the real iPhoneOS PacketTunnel archive build, but
Rust build scripts again failed with `ld: library 'System' not found`.
Merely invoking Cargo with `env -u SDKROOT` removed the incorrect iPhoneOS
SDK yet also left macOS host linking without an SDK. This explicitly
**invalidates** the earlier assumption that unsetting SDKROOT was sufficient.

The narrowly scoped correction uses
`SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" cargo build --target ...`.
macOS-host build scripts receive the real MacOSX.sdk. Rust's platform-aware
iOS compiler/cc integration must still discover the selected iPhoneOS or
simulator SDK from its explicit target triple; this claim requires actual
CI link evidence. The wrapper mock checks both iPhoneOS inheritance and
missing host SDK. Keep #63, #52, #13, #39 and #55 OPEN until native proof.
No signed iPhone or independent external challenge review occurred.

## 2026-11-20 — License graph review correction (#64)

The initial inventory joined *all* workspace packages, accidentally
including unrelated `boringtun-cli`. Reaching the BoringTun library's
dependency closure removed that sibling, but Cargo's resolution still
included dev/bench `page_size@0.6.0` declaring legacy
`MIT/Apache-2.0` syntax. We now traverse only Cargo dependency edges of
kind normal or build for the shipped `ffi-bindings` library, **excluding**
dev-only edges; an offline negative regression fixture proves this.
The parser continues to reject unreviewed/ambiguous license syntax for
actual production/build deps. This is not license text distribution proof,
nor a binary object/symbol inventory; #55/#31 remain open.
