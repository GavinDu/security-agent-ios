# ADR-0002 — Rust BoringTun for the iPhone PacketTunnel

**Status:** Product owner directed, 2026-11-20. Supersedes ADR-0001.
**Epic:** #6; child issues #51–#56. Native/device acceptance is pending.

## Design

```text
AgentApp.app (SwiftUI)
  ├── Keychain, pairing QR, NETunnelProviderManager, VPN-gated WKWebView
  └── embeds PacketTunnel.appex
      ├── Swift NEPacketTunnelProvider / NEPacketTunnelFlow
      ├── Swift NWConnection encrypted UDP transport
      ├── Swift serial handshake/rekey/lifetime scheduler
      └── C FFI → Rust BoringTun libboringtun.a (WireGuard protocol)
Mac Mini (separate machine): WireGuard peer/server and private agent backend
```

No Go compiler, Go archive, WireGuardKitGo, Go runtime, or Go process
is part of the iPhone project. BoringTun is not a NetworkExtension adapter;
it implements the WireGuard protocol without the packet-flow/UDP stack.
The old WireGuardKit adapter cannot be used as a Rust ABI compatibility layer.

## Source & build

Cloudflare BoringTun 0.7.1 pinned Git commit
`253f7afb2b3df9e952065d10bf2af19913cb176b`.
Rust 1.90.0, Cargo `--locked`, upstream Cargo.lock, source-only
checkout. The native PacketTunnel target builds a separate static archive
for iPhoneOS arm64 or iOS Simulator arm64/x86_64, and links
`libboringtun.a`; `BoringTunBridge.h` imports the exact upstream
`wireguard_ffi.h`. The iPhone UI does not import the C FFI or Rust symbols.
BoringTun is BSD-3-Clause; Cargo dependency licenses still need audit.

## Principal iOS/Swift architectural challenge

- Verify Swift import of C enums, result structs and opaque handles against
  real Xcode 16.4, not merely Swift source parsing.
- Serialize every BoringTun C call and free on one queue. Enforce output
  buffer lengths, reject untrusted packet sizes, and do not log keys.
- A successful UDP connection is not an authenticated WireGuard handshake:
  report start success only after BoringTun confirms handshake, with timeout.
- On stop/roaming/rekey, avoid accessing a freed C tunnel. Test lifecycle
  races on real hardware.
- Test UDP socket route exclusion (avoid tunnel recursive routing), DNS,
  IPv6/full split paths, roaming and background suspend/resume.
- Cloudflare upstream [issue #495](https://github.com/cloudflare/boringtun/issues/495)
  reports one-way traffic liveness failures with 0.7.1; not universal proof,
  but blocks a claim of release safety without rekey/long traffic tests.
- Build output, signing and actual Mac peer test are not interchangeable;
  never claim a working VPN merely from green CI.

## Decisions and alternatives

Go WireGuardKitGo is rejected by explicit user requirement.
External WireGuard/Tailscale shifts VPN ownership outside this app and
does not meet in-app control. Native IKEv2 changes server protocol.
A bespoke Swift WireGuard cryptographic engine would add unjustified
security risk. BoringTun is therefore the selected Rust protocol engine.

ProtonLumo/ios-lumo remains a SwiftUI/Tuist architectural reference;
no GPL source code has been imported.

This is a rigorous **structured self-review**, not approval by an
independent principal Swift/iOS reviewer or proof of a signed iPhone.
