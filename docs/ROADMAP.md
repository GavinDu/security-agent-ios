# Security Agent iOS — active Rust roadmap

The current protocol engine is pinned Rust BoringTun 0.7.1 linked solely
into the Swift PacketTunnel extension. CI-native iPhoneOS compile/link,
simulator XCTest, signed iPhone handshake, and stable Mac peer routing
must each be proven before claiming a working VPN.

## Independently closeable phases

1. [Foundation #6](https://github.com/GavinDu/security-agent-ios/issues/6): Rust archive/ABI #52/#53, iPhone transport #54, native CI/license #13/#39/#55,
   panic and memory safety #58, liveness #57, signing #40, branch protection #48.
2. [VPN lifecycle #7](https://github.com/GavinDu/security-agent-ios/issues/7): startup/teardown #14, permission-safe persistence #15,
   roaming/on-demand #16, bounded diagnostics #17.
3. [Pairing #8](https://github.com/GavinDu/security-agent-ios/issues/8): public identity verification #4/#18, QR import #19,
   address allocation #20, authenticated PSK #21, rotation/revocation #22.
4. [Agent chat #9](https://github.com/GavinDu/security-agent-ios/issues/9): WebView isolation #23, JS bridge #24,
   offline state #25 and voice #26.
5. [Routing and Mac gateway #10](https://github.com/GavinDu/security-agent-ios/issues/10): E2E #3, Mac server #27, split/DNS #28,
   full IPv4/IPv6 #29 and safe transitions #30.
6. [Hardening and TestFlight #11](https://github.com/GavinDu/security-agent-ios/issues/11): review #5/#31, signing #32,
   accessibility #33, soak #34, Rust host SDK #63, completed Cargo inventory #64,
   UDP underlay route isolation #65.

## Acceptance and security policy

- Close atomic issues on matching-source test evidence, not waiting for all phases.
- Preserve failures in native GitHub Actions; do not bypass required checks.
- Use the pinned BoringTun C ABI, Rust and Cargo.lock; no unreviewed binaries.
- Never place private keys, PSKs, session tokens or signing material in Git.
- Mac listener deployment, Apple entitlements, full/split routes, roaming
  and real-device stability are separate physical-environment gates.
- Consult [ADR-0002](ADR-0002-RUST-BORINGTUN.md),
  [ARCHITECTURE](ARCHITECTURE.md) and [BORINGTUN_BUILD](BORINGTUN_BUILD.md).

Historical migration decisions and retired work remain in Git history and
closed issue records, not in active implementation instructions.
