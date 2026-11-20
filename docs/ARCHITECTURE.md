# Architecture

```text
iPhone SwiftUI AgentApp
  ├── VPN status + modes → NETunnelProviderManager (public profile only)
  ├── Pairing QR → CryptoKit X25519 + shared Keychain
  └── VPN-gated WKWebView → http://10.8.0.1:8080/chat

Shared Keychain (same Apple Team, iPhone App + PacketTunnel only)
  ├── iPhone WireGuard X25519 private key (AfterFirstUnlockThisDeviceOnly)
  └── optional pre-shared key (not generated until matching Mac provision)

App Group (nonsecret)
  └── public Mac peer key, endpoint, split/full mode, on-demand flag

PacketTunnel extension, independent of App UI lifecycle
  └── NEPacketTunnelProvider → WireGuardKit Adapter → utun

Mac Mini
  ├── AgentMac SwiftUI pairing utility (public values + QR)
  ├── wireguard-tools/wireguard-go via system daemon, not embedded in UI
  ├── WireGuard peer for iPhone 10.8.0.2/32
  └── agent HTTP application bound to 10.8.0.1:8080
```

## Pairing contract, version 1

QR codes contain JSON:
- iPhone: `{"version":1,"kind":"iphone","publicKey":"<base64>"}`
- Mac: `{"version":1,"kind":"mac","publicKey":"<base64>","endpoint":"host.example:51820"}`

No QR contains the private key or PSK. Exchange keys over a channel where
the endpoint/public-key authenticity can be verified out of band. A QR code
is a transport, not authentication by itself. Register the iPhone public
key in the Mac Mini WireGuard peer configuration first.

## Threat model

- Lost phone: private key is not cloud-synced; use device protection,
  revoke the peer on Mac, and rotate keys when needed.
- Malicious QR: validate JSON version, kind, 32-byte public key and endpoint.
  Confirm the displayed public-key fingerprint with the Mac before connecting.
- Malicious web content: restrict WebView navigation to
  `http://10.8.0.1:8080`; whitelist bridge messages; do not expose credentials.
- VPN off: the UI must not instantiate/load the agent WebView.
- DNS: no VPN DNS override for split; use public DNS only in full.
- Reconnection: NetworkExtension and WireGuardAdapter handle network path
  changes; on-demand is optional and must be tested on real hardware.
- Full tunnel: server requires NAT and correctly routed IPv6. Avoid describing
  this as a fail-closed kill switch until OS behavior is verified.
