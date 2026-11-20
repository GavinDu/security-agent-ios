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
