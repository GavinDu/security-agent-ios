# Dependencies by platform

## iPhone / iPad

| Component | Library / framework | Integration |
| --- | --- | --- |
| UI | SwiftUI, Foundation | Apple SDK |
| Packet tunnel / on-demand | NetworkExtension | Apple entitlement required |
| Tunnel transport | Swift NetworkExtension + Network.framework | Native iOS PacketTunnel extension |
| WireGuard crypto | Cloudflare BoringTun BSD-3-Clause | Pinned Rust staticlib, C FFI; see BORINGTUN_BUILD.md |
| Chat | WebKit (WKWebView) | Apple SDK |
| Private key generation | CryptoKit (Curve25519.KeyAgreement) | Apple SDK |
| Secret persistence | Security (Keychain Services) | Shared Keychain access group |
| Pairing scan | AVFoundation | Camera permission |
| Pairing output | CoreImage, CoreImage.CIFilterBuiltins | QR generation |
| Speech | Speech, AVFoundation | Optional later phase |
| Diagnostics | OSLog | Apple SDK |
| Build | Xcode, Tuist, Swift Package Manager | Development machine |
| Testing | XCTest | Apple SDK |

**Not needed for v1:** Alamofire, SQLite, Firebase, CocoaPods, Lottie,
SwiftUIIntrospect, ProtonUIFoundations. Proton Lumo's implementation pulls
Lottie and an internal Proton UI foundations dependency, which is unsuitable
as a mandatory prerequisite for this independent application.

## Mac Mini desktop + server

| Component | Library / tool | Integration |
| --- | --- | --- |
| Companion UI | SwiftUI, AppKit, Foundation | Apple SDK |
| Pairing QR | CoreImage | Apple SDK |
| Local status/keys | Security, OSLog | Apple SDK |
| WireGuard server | `wireguard-tools` | Homebrew `brew install wireguard-tools` |
| Userspace fallback | `wireguard-go` | When required by wireguard-tools/macOS |
| Startup | `launchd` | macOS system daemon |
| IP forwarding / NAT | `sysctl` + `pf` | Only for full tunnel, requires privileged setup |
| Agent backend | User's HTTP service at `10.8.0.1:8080` | Launchd or containers |
| Remote endpoint | Public DNS/DDNS record and UDP 51820 forward | Router setup |

The Mac Mini is the **WireGuard server**, not a second iOS packet tunnel;
the desktop app need not embed WireGuardKit just to present pairing QR codes.
Use the official WireGuard app or securely managed WireGuard command-line tools
to actually run the server.

## Upstream sources and licensing

- [Cloudflare BoringTun](https://github.com/cloudflare/boringtun) — BSD-3-Clause, pinned tag 0.7.1, commit `253f7afb2b3df9e952065d10bf2af19913cb176b`. Audit all statically linked Cargo crates and the reported liveness regression before release.
- [Proton Lumo iOS](https://github.com/ProtonLumo/ios-lumo) — Tuist / SwiftUI architectural reference; GPL-3.0. No source copied.
- [Apple NetworkExtension](https://developer.apple.com/documentation/networkextension) — system VPN API.
