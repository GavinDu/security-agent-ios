# Security Agent — iPhone + Mac Mini

Native SwiftUI applications for secure, self-hosted agent access through WireGuard.
The iPhone loads the private agent web UI only after iOS reports a connected VPN.
The Mac Mini companion provides pairing QR generation and peer enrollment guidance.

**Status (CI-verified unsigned Foundation, November 22, 2026):** the native
iPhoneOS app and PacketTunnel compile and link pinned Rust Cloudflare BoringTun,
iOS Simulator XCTest passes, and the SwiftUI Mac companion builds in
[main-branch Actions #45060469690](https://github.com/GavinDu/security-agent-ios/actions/runs/45060469690).
These checks do **not** establish Apple signing/entitlements on a physical
iPhone, an authenticated connection to a real Mac peer, safe full-tunnel routes,
or release approval. See [docs/BORINGTUN_BUILD.md](docs/BORINGTUN_BUILD.md)
for native prerequisites and outstanding device gates.

## Applications

- **AgentApp (iPhone/iPad):** SwiftUI chat gate, VPN status/settings, QR pairing, WebKit UI at
  `http://10.8.0.1:8080/chat`.
- **PacketTunnel (iOS extension):** Swift `NEPacketTunnelProvider` + Rust BoringTun via C FFI;
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
3. Run `mise install` followed by `bash scripts/setup-project.sh`.
   The setup script fetches exact pinned BoringTun Rust source and generates
   the Xcode project. PacketTunnel's pre-build phase compiles a Rust static
   archive for the selected iOS SDK and architecture. See [docs/BORINGTUN_BUILD.md](docs/BORINGTUN_BUILD.md)
   for supported toolchain versions and native CI requirements.
4. Open the generated project and
   build `AgentApp` to a **physical iPhone** for VPN testing.
5. Build `AgentMac` on macOS. Configure your Mac WireGuard server separately,
   then enter its public key and DNS endpoint to display a pairing QR.
6. Pair: generate iPhone identity → register its public key as a Mac peer
   (`10.8.0.2/32`) → scan the Mac pairing QR → Save VPN → Connect.

Track all six phases and their independently verifiable work items in
[docs/ROADMAP.md](docs/ROADMAP.md). The GitHub epic checklist is the live issue tracker.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/DEPENDENCIES.md](docs/DEPENDENCIES.md), and [docs/MAC_SERVER.md](docs/MAC_SERVER.md).

## Security notes

- **Never commit** private keys, PSKs, `.conf` files containing secrets, or provisioning profiles.
- Only public peer metadata appears in App Group defaults and the VPN manager's
  `providerConfiguration`. The iPhone X25519 private key uses an access-group Keychain
  item with `AfterFirstUnlockThisDeviceOnly` protection.
- Only the chat WebView receives the ATS web-content HTTP exception; the VPN protects
  transport to a trusted home agent, but the agent must authenticate users itself.
- **Active routing: split-only.** The app and PacketTunnel both reject full-tunnel
  activation before installing any `0.0.0.0/0` or `::/0` routes. Full mode is
  intentionally disabled pending signed iPhone/Mac verification of underlay
  isolation, NAT64/IPv6 and leak/fail-close behavior
  ([#65](https://github.com/GavinDu/security-agent-ios/issues/65),
  [#29](https://github.com/GavinDu/security-agent-ios/issues/29)).
  Split mode leaves ordinary web and DNS traffic on the regular network; do
  not treat it as a device-wide kill switch.
- On-demand is **opt-in** for a correctly configured split-tunnel profile;
  signed-device connection/roaming reliability is still unverified.
- The browser bridge has an allowlist and does not expose VPN credentials.
- Proton Lumo was consulted for architecture only. **No Proton GPLv3 source was copied.**

## Roadmap / verification

- Phase 0: Tuist + app/extension targets (unsigned native build and simulator XCTest
  verified in Actions #45060469690; signed physical-device build not verified)
- Phase 1: VPN manager and Rust adapter source (real iPhone/Mac handshake unverified)
- Phase 2: QR payloads and Keychain identity (basic UI; full automated peer enrollment pending)
- Phase 3: VPN-gated chat WebView (streaming is provided by the web backend)
- Phase 4: Split-route safety and pre-route DNS pinning (full mode deliberately
  blocked; physical DNS/MTU/IPv6/NAT64/roaming route tests pending)
- Phase 5: Device QA, on-demand, TestFlight and crash/logging hardening pending
