# Security Agent iOS — roadmap and GitHub issue breakdown

**Status:** An initial source scaffold exists on PR #1. Neither the native
WireGuardKitGo bridge nor an Apple-signed VPN handshake has been verified.
The physical Mac Mini's WireGuard/agent service is separately configured.

## Build order and dependency graph

1. [Phase 0 — Foundation](https://github.com/GavinDu/security-agent-ios/issues/6):
   dependency pinning (#12), native link/build (#2), CI compile/test (#13).
2. [Phase 1 — VPN Core](https://github.com/GavinDu/security-agent-ios/issues/7):
   provider lifecycle (#14), VPN manager permission/status (#15), roaming/on-demand
   (#16), private diagnostics (#17).
3. [Phase 2 — Pairing & Keys](https://github.com/GavinDu/security-agent-ios/issues/8):
   baseline authenticated pairing (#4), verified Mac fingerprint (#18),
   Mac QR import (#19), peer address allocation (#20), optional PSK (#21),
   key rotation and revocation (#22).
4. [Phase 3 — Agent UI](https://github.com/GavinDu/security-agent-ios/issues/9):
   WebView isolation (#23), versioned JS bridge (#24), offline/streaming state
   (#25), voice transcription (#26).
5. [Phase 4 — Routing](https://github.com/GavinDu/security-agent-ios/issues/10):
   physical device E2E (#3), Mac endpoint/launchd (#27), split/DNS (#28),
   full NAT/IPv6 (#29), route transitions (#30).
6. [Phase 5 — Hardening & TestFlight](https://github.com/GavinDu/security-agent-ios/issues/11):
   device release gate (#5), security/licensing review (#31), signed TestFlight
   (#32), accessibility (#33), 72-hour soak (#34).

## General definition of done

- A child issue closes when its own acceptance criteria pass; do not wait
  for all other epics to close.
- Add deterministic tests, supported logs or redacted screenshots for proof.
- Parser-only workflows are not native build evidence.
- Merge PRs only after all required GitHub Actions checks pass.
- VPN networking, iPhone background execution, Mac NAT and TestFlight need
  physical devices, networking access and owner-controlled signing.
- **Never** upload WireGuard private keys, PSKs, provisioning or session tokens.

## QR pairing threat model

The public QR contains an unauthenticated key and endpoint. A nearby attacker
can replace it with their own public key. The iPhone therefore displays a
SHA-256 fingerprint of the key and requires user confirmation against the same
fingerprint on a trusted Mac display before saving. This is still manual
out-of-band authentication; it does not authenticate a QR automatically.
Issue #18 tracks full pairing acceptance and negative tests.

### Foundation SwiftPM compatibility issue

- [#42: Repair pinned WireGuard Apple manifest](https://github.com/GavinDu/security-agent-ios/issues/42): immutable vendor source + fail-closed tools-version overlay, tracked separately from #2/#12/#38. Requires native CI evidence to close.
