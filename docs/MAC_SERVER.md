# Mac Mini — Rust WireGuard server boundary

AgentMac is a SwiftUI pairing companion, **not** the VPN daemon. The user
must deploy and administer a separate macOS WireGuard peer. This project
selects the Rust BoringTun implementation for the userspace protocol engine;
do not silently select an alternate system userspace backend.

## Provisioning outline (not a proven deployment script)

1. Build or install a reviewed and pinned `boringtun-cli` Rust binary for
   macOS. Confirm the executable path and version before using it as a
   privileged launchd service. The iOS BoringTun staticlib is a different
   artifact; do not attempt to run it as a Mac server.
2. Install `wireguard-tools` only for the `wg` key/configuration utility,
   if required. Starting a tunnel through an unqualified `wg-quick up`
   may select an unintended userspace backend. If using `wg-quick`, set
   `WG_QUICK_USERSPACE_IMPLEMENTATION` explicitly to the audited Rust CLI
   path and verify the running process. Check upstream CLI compatibility
   with the installed macOS and launchd environment before enabling it.
3. Generate a server private/public key pair **on the Mac**, protect
   `/etc/wireguard` (root ownership, mode 0700), and keep secrets out of Git.
4. Provision a listening UDP port and peer mapping, verify privileged
   interface setup, DNS, routing and restart behavior. Issue #27 tracks
   the real Mac gateway acceptance, not just configuration syntax.

Example public peer addressing (replace placeholder keys locally):

```ini
[Interface]
PrivateKey = <MAC_PRIVATE_KEY>
Address = 10.8.0.1/24, fd86:ea04:1111::1/64
ListenPort = 51820

[Peer]
PublicKey = <IPHONE_PUBLIC_KEY_FROM_QR>
AllowedIPs = 10.8.0.2/32, fd86:ea04:1111::2/128
```

Use `wg show` against the **verified Rust** tunnel to check peer
handshake and transfer counters; do not upload private keys or raw packet
logs. Mac peer public key and endpoint are displayed in AgentMac for
out-of-band fingerprint confirmation on iPhone.

## Network and safety validation

- Forward UDP 51820 to the Mac only when endpoint exposure is intended.
- Bind the agent HTTP service at `10.8.0.1:8080` to a trusted route; enable
  backend authorization/CSRF checks independent of VPN status.
- Split tunnel should route only `10.8.0.0/24` and preserve ordinary
  public DNS/internet routing on the phone.
- Full tunnel requires scoped IPv4 forwarding/NAT and either a working
  IPv6 path or an explicitly tested fail-safe policy. Never overwrite
  the Mac's global pf configuration to make a demo work.
- Verify traffic both ways, iPhone lock/background, Wi-Fi/cellular roam,
  reconnect, DDNS updates, key revocation and service restart.
- No Mac listener, launchd service or signed iPhone tunnel is verified by
  this document. Track server and routing tests in #27–#30 and #54/#65.

Upstream Rust CLI reference: https://github.com/cloudflare/boringtun


## Multi-device enrollment implementation boundary (#20)

The shared Swift roster coordinator serializes proposed public peer changes
within one process. It checks an exact epoch/revision/roster snapshot, allocates
a unique slot, revokes only the exact key/slot pair, and holds a pending
transaction until complete authoritative readback matches the proposed or
original roster. The daemon must fence all asynchronous writes before providing terminal
readback; an earlier snapshot is not rollback evidence. Ambiguous readback
blocks further changes. Rollback advances
the revision; stale callbacks cannot settle another plan.

This is not a daemon, durable roster, authenticated enrollment protocol,
or live peer installer. It is intentionally not wired into the Mac copy
button or PacketTunnel. The app remains single-device at .2. Before enabling
multiple devices, #20 must integrate a durable journal, authenticated Mac
authorization, actual Rust daemon apply/readback, and client-address binding
in the versioned iOS profile. Restart must recover pending operations from
authoritative state, not construct an empty roster.


## Public-only daemon inventory boundary (#20)

The independent inventory validator accepts only the public outputs of
`wg show <verified-interface> public-key`, `peers`, and `allowed-ips`,
using the single-interface format (not `all`). The expected server public
key must match; peer keys must be unique and identical across both peer
queries; every managed peer must own exactly its paired /32 and /128 host
routes with a unique slot. Missing, extra, malformed, truncated or noncanonical
rows are rejected. Never use `dump`, `showconf`, private-key or PSK output.
An empty peer list is valid only if both peer queries successfully completed
without truncation. The actual daemon owner must bound capture before parsing,
verify executable/interface/server identity, serialize writes and provide a
terminal fence across the three queries; this parser is not proof of those
properties. It is not invoked by the current UI, does not perform privileged
operations, and cannot enable a second iPhone. Gateway deployment remains #27.
