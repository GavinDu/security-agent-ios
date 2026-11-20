# ADR-0001: iPhone SwiftUI app and WireGuard backend boundary

**Status: superseded by [ADR-0002](ADR-0002-RUST-BORINGTUN.md) at the user's direction (2026-11-20).** This page is historical and does not describe the current build.
**Scope:** [Epic #6](https://github.com/GavinDu/security-agent-ios/issues/6),
[architecture issue #50](https://github.com/GavinDu/security-agent-ios/issues/50).
**Review:** principal-level critical Swift/iOS self-review; no external
independent reviewer or real-device approval has been obtained.

## Decision and product boundary

**This is an iPhone app, implemented in Swift/SwiftUI. Go is *not* our
application language or an on-device Go server.** The only reason Go exists
in the current toolchain is that the official WireGuardKit adapter calls
the WireGuard userspace protocol engine built from `wireguard-go`.

For the currently required first-party **in-app VPN pairing, connect,
disconnect, split/full route controls and background packet tunnel**, retain:

```
AgentApp.app (SwiftUI, NetworkExtension VPN manager, Keychain, QR, WKWebView)
    embeds PacketTunnel.appex; does not directly link WireGuardKit or Go
PacketTunnel.appex (Swift NEPacketTunnelProvider + WireGuardKit)
    statically links pinned libwg-go.a (WireGuard protocol backend)
Mac Mini (separate machine)
    runs WireGuard listener/agent server, not an iPhone Go service
```

Only the PacketTunnel target runs the bridge build phase, and CI includes
a static target/source-boundary test to prevent unintended imports into
AgentApp or AgentMac. No separately installed Go runtime, Go CLI, daemon or
Go HTTP service is required on the iPhone. The Go runtime code required by
the library is part of the linked binary.

Apple's NetworkExtension provides tunnel lifecycle, routing and packet
flow; it **does not provide a built-in WireGuard cipher/protocol engine**.
Removing `wireguard-go` while retaining custom in-app WireGuard requires
another protocol implementation, not simply more SwiftUI.

## Alternatives and trade-offs

| Option | Go in our iOS app? | In-app VPN control? | Impact |
| --- | --- | --- | --- |
| **Keep pinned WireGuardKit + wireguard-go** | Only embedded static backend in PacketTunnel | Yes | Preserves existing Mac WireGuard server; requires Go/Xcode ABI CI, license and signing validation |
| Existing **WireGuard or Tailscale iOS app** | No | No control of another provider's tunnel via our NETunnelProviderManager | Lowest app build complexity; VPN owned/set up separately; change pairing, status and UX semantics |
| **Apple IKEv2/IPsec** via NEVPNManager | No | Yes, for Apple's protocol | Mac Mini server must also be migrated/configured for IKEv2, certificates and identity distribution |
| **BoringTun (Rust)** | No Go, but embeds Rust | Possible with new packet transport/FFI adapter | New supply-chain, platform and real-device tests; not a drop-in replacement for WireGuardKit |
| Write WireGuard protocol/crypto in **Swift** | No | Theoretically | Reject: bespoke cryptography/protocol implementation is outside scope and unjustified |

**No-Go migration trigger:** If the product owner explicitly drops the
requirement that this app controls an integrated VPN, choose a separate
managed WireGuard/Tailscale connection, then remove PacketTunnel, Go,
Tuist WireGuard dependency, Network Extension packet-tunnel entitlements,
and in-app VPN connect/disconnect behavior in a dedicated migration PR.
Do not silently make this change in a source-compatibility bugfix.

**IKEv2 migration trigger:** If integrated VPN management remains necessary
but dropping WireGuard compatibility is acceptable, test Apple-native IKEv2
with a compatible Mac Mini server before removing PacketTunnel.

## Principal Swift/iOS architect challenge

1. **App/extension isolation:** test the native target/link graph as well
   as source imports; the SwiftUI app should not invoke Go or manage IP
   packets. Extension owns a bounded native dependency.
2. **Memory & battery:** static Go in a Packet Tunnel extension increases
   footprint and background lifecycle complexity; measure on physical
   iPhone before signing off. No fabricated performance claim.
3. **Build reproducibility:** pinned 2023 WireGuard Apple + Go 1.19.13
   requires a SwiftPM header compatibility overlay, exact vendor SHA,
   architecture-specific archives and honest native CI. See #2/#36/#37.
4. **Security/licensing:** audit linked Go modules on **GOOS=ios**, rather
   than treating all indirect go.mod dependencies as shipped iOS code;
   see #12/#49. No Lumo GPL source is imported.
5. **Platform integration:** NetworkExtension entitlement, shared Keychain,
   App Group, VPN permission and real-device handshake must be verified
   separately; see #40. An iOS simulator is not equivalent.
6. **Generated files:** Tuist 4.218.1 creates five specific metadata
   files in the pinned WireGuard checkout. Fail closed on all untracked
   source files while explicitly allowing only those five generated paths;
   see #47. Do not disable integrity checks to make CI green.

## References

- Apple's [NetworkExtension](https://developer.apple.com/documentation/networkextension)
  and [Personal VPN](https://developer.apple.com/documentation/networkextension/personal-vpn)
  documentation describe packet providers versus built-in IKEv2/IPsec.
- Official [WireGuard Apple source](https://github.com/WireGuard/wireguard-apple)
  uses WireGuardKit and a wireguard-go bridge.
- [Cloudflare BoringTun](https://github.com/cloudflare/boringtun)
  supports a Rust WireGuard protocol implementation, not an Apple UI or
  out-of-the-box NEPacketTunnelProvider integration.

**Decision is architectural only.** Device archive, simulator XCTest,
Apple signing and live Mac Mini handshake gates remain pending.
