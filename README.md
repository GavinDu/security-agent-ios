# Security Agent — iPhone + Mac Mini

Native SwiftUI applications for secure, self-hosted agent access through WireGuard.
The iPhone loads the private agent web UI only after iOS reports a connected VPN.
The Mac Mini companion provides pairing QR generation and peer enrollment guidance.

**Status (initial scaffold):** SwiftUI apps, Keychain-backed identity, pairing QR,
NetworkExtension manager and packet-tunnel adapter source are provided. This does
**not** certify that WireGuardKitGo is built, developer entitlements have been granted,
VPN connectivity has been tested on an iPhone, or that the Mac is an operational VPN server.
See [docs/WIREGUARD_BUILD.md](docs/WIREGUARD_BUILD.md) for native prerequisites.

## Applications

- **AgentApp (iPhone/iPad):** SwiftUI chat gate, VPN status/settings, QR pairing, WebKit UI at
  `http://10.8.0.1:8080/chat`.
- **PacketTunnel (iOS extension):** `NEPacketTunnelProvider` + `WireGuardAdapter`;
  reconstructs the tunnel in memory from a shared Keychain secret and a public
  App Group profile. No full wg-quick config or private key is saved in VPN preferences.
- **AgentMac (macOS):** SwiftUI pairing console showing the Mac's public WireGuard
  key and endpoint as QR code; displays peer commands but never executes privileged
  changes without an administrator.
- **Shared:** key storage, public pairing payloads, and route mode.

## Build

1. On a Mac with current Xcode, Tuist and the required Apple Developer account, enable
   Network Extensions / Packet Tunnel, App Groups and App Group access on both
   iPhone bundle IDs. Use the same Team ID for both. Register the App Group.
2. Set `AGENT_APP_TEAM_ID=<YOUR_TEAM_ID>` in your shell.
3. Build the **WireGuardKitGo** device/simulator library as described in
   [docs/WIREGUARD_BUILD.md](docs/WIREGUARD_BUILD.md) first.
4. Run `tuist install && tuist generate`, open the generated project and
   build `AgentApp` to a **physical iPhone** for VPN testing.
5. Build `AgentMac` on macOS. Configure your Mac WireGuard server separately,
   then enter its public key and DNS endpoint to display a pairing QR.
6. Pair: generate iPhone identity → register its public key as a Mac peer
   (`10.8.0.2/32`) → scan the Mac pairing QR → Save VPN → Connect.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/DEPENDENCIES.md](docs/DEPENDENCIES.md), and [docs/MAC_SERVER.md](docs/MAC_SERVER.md).

## Security notes

- **Never commit** private keys, PSKs, `.conf` files containing secrets, or provisioning profiles.
- Only public peer metadata appears in App Group defaults and the VPN manager's
  `providerConfiguration`. The iPhone X25519 private key uses an access-group Keychain
  item with `AfterFirstUnlockThisDeviceOnly` protection.
- Only the chat WebView receives the ATS web-content HTTP exception; the VPN protects
  transport to a trusted home agent, but the agent must authenticate users itself.
- Split tunnel leaves normal DNS and web traffic on the regular network. Full tunnel
  configures `0.0.0.0/0` and `::/0`; correct IPv6 routing/NAT is a server requirement.
- On-demand is **opt-in**, not enabled by default, until a user has verified server
  connectivity and understood full-tunnel fail-closed behavior.
- The browser bridge has an allowlist and does not expose VPN credentials.
- Proton Lumo was consulted for architecture only. **No Proton GPLv3 source was copied.**

## Roadmap / verification

- Phase 0: Tuist + app/extension targets (device build not verified)
- Phase 1: VPN manager and adapter source (device connect not verified)
- Phase 2: QR payloads and Keychain identity (basic UI; full automated peer enrollment pending)
- Phase 3: VPN-gated chat WebView (streaming is provided by the web backend)
- Phase 4: Split/full routing mode toggle (Safari, DNS, MTU and roaming tests pending)
- Phase 5: Device QA, on-demand, TestFlight and crash/logging hardening pending
