# Security Agent iOS — active architecture

## Deployment boundaries

```text
AgentApp.app (SwiftUI)
  ├── NETunnelProviderManager (system VPN configuration, status, user consent)
  ├── pairing QR / CryptoKit X25519 / shared Keychain
  └── VPN-gated WKWebView -> private agent at 10.8.0.1:8080
PacketTunnel.appex (Swift, NetworkExtension)
  ├── NEPacketTunnelFlow and tunnel network settings
  ├── Network.framework encrypted UDP underlay (routing pending #65)
  ├── serial lifecycle, handshake and timer orchestration
  └── Cloudflare BoringTun 0.7.1 Rust staticlib via upstream C ABI
Shared App Group: public peer endpoint, public key, route mode and bounded events
Shared Keychain: iPhone X25519 private key and optional PSK (never App Group)
Mac Mini: separately managed Rust BoringTun WireGuard server + AgentMac pairing UI
```

The iOS app and Mac SwiftUI companion do not link the BoringTun static library.
Only PacketTunnel owns the C bridging header and Rust archive. The iOS app
does not run a separate VPN service or expose private keys to the WebView.

## Versioned QR pairing

- iPhone: `{"version":1,"kind":"iphone","publicKey":"<base64>"}`
- Mac: `{"version":1,"kind":"mac","publicKey":"<base64>","endpoint":"host.example:51820"}`
- Only public material is encoded. A QR is not authentication: compare the
  displayed Mac public-key fingerprint through a trusted second channel.
- Key rotation and per-client address allocation remain #20–#22.

## Threat model and constraints

- Private key: device-local, not synced or logged. Revoke a lost device on Mac.
- WebView: only private agent origin after VPN connectivity; origin and JS
  bridge isolation are independently tracked in #23 and #24.
- PacketTunnel: serial Rust C-ABI calls, bounded buffers, authenticated
  handshake before start completion. iPhone runtime testing remains #53/#58.
- Split tunnel: no DNS override or public internet redirect. **Full tunnel
  is currently fail-closed** in both the app and PacketTunnel: a persisted
  full-mode profile cannot install default routes until a signed iPhone
  proves safe encrypted UDP underlay and IPv4/IPv6/DNS behavior (#71/#65/#29).
- Roaming and BoringTun 0.7.1 rekey/liveness require signed device evidence (#57).
- Apple signing, entitlement validity and protected CI cannot be inferred
  from Linux checks or an unsigned Xcode build (#40/#48).

## Current design decision

[ADR-0002](ADR-0002-RUST-BORINGTUN.md) is the authoritative backend decision.
See [BORINGTUN_BUILD](BORINGTUN_BUILD.md) for reproducible native builds,
[MAC_SERVER](MAC_SERVER.md) for peer provisioning, and
[ARCHITECT_REVIEW_P0](ARCHITECT_REVIEW_P0.md) for open security gates.
