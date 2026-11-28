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

This is not a daemon, authenticated enrollment protocol, or live peer installer. It is intentionally not wired into the Mac copy
button or PacketTunnel. The app remains single-device at .2. Before enabling
multiple devices, #20 must integrate the persistent journal with authenticated Mac
authorization, actual Rust daemon apply/readback, and client-address binding
in the versioned iOS profile. Restart must recover pending operations from
authoritative state, not construct an empty roster.


### Persistent public roster journal

The next #20 slice implements a versioned canonical public roster record
with current epoch/revision and pending before/after plan, scoped to a Mac
public key. The daemon must explicitly bootstrap from a complete verified
roster in a daemon-owned private local 0700 directory; automatic restart only opens an
existing validated record. All cooperating writers use the persistent lock
inode and compare-and-swap on the exact record. Prepare persists before
returning a plan, and settlement persists before clearing pending state.
A failed write blocks that actor; restart must re-open and reconcile. File
and directory sync are required before acknowledging the write. Unknown,
oversized, noncanonical, wrong-server or inconsistent data fails closed.
The record contains only public keys, address slots, and transaction metadata.
A server key cannot be enrolled as its own client peer. The lock must be an
owner-controlled, single-link 0600 regular file; never unlink it during use.

This is restart recovery infrastructure, not authenticated enrollment or
actual daemon integration. The owner must protect the directory and lock
inode, supply a complete terminal fenced readback, and never treat a
caller Boolean as proof of a real Rust daemon fence. Real power-loss,
permissions, multi-process and hardware acceptance remain outstanding.
The current UI/PacketTunnel still cannot activate a second client slot.

### Fresh public inventory gate

A persistent coordinator now refuses every prepare unless a structurally validated
same-server inventory exactly matches the current journal roster under the daemon
owner's terminal write fence. Raw roster arrays cannot settle a persistent plan;
settlement requires the public inventory parser's snapshot, the exact transaction
ID and same server. A fresh read is required for each mutation, not a cached
startup-ready flag. The parser and a caller-supplied fence flag do not prove actual
process ownership, freshness or exclusivity. The future privileged Rust daemon
owner must hold the exclusive mutation fence across capture, prepare, apply and
settlement, and prevent alternate writers. No live daemon or extra iPhone slot is
activated by this change.

### Mutual out-of-band public-key confirmation

Before the Mac companion reveals or copies a single-device peer stanza, the
administrator must compare the full SHA-256 fingerprint with the trusted
iPhone screen and explicitly confirm the exact client public key, Mac public
key and endpoint preview. Editing any input or starting/importing/canceling a
new scan clears approval. A self-peer is refused. The iPhone displays the same
canonical fingerprint algorithm for its own public key. This is local human
approval for a public configuration preview, not proof of possession, daemon
authorization, address availability, or successful enrollment. The administrator
must still verify the actual Rust daemon and slot ownership; no sudo or live
mutation is invoked by this UI.

### Fenced mutation executor contract (#20)

A non-reentrant actor now sequences an injected trusted owner's exact-intent
lease, same-generation initial public inventory, durable journal prepare,
one apply attempt, terminal inventory and durable settlement. Failed or
canceled dispatch cannot imply rollback; missing, stale or divergent terminal
evidence preserves pending state. Recovery is terminal readback only and does
not apply again. The lease is always released through its owner, whose
contract requires quarantine of outstanding writes before future acquisition.
The executor reopens the journal under the lease, never bootstraps on failure,
and exposes no private material. Native and compiled Swift fixtures exercise
authorization rejection, stale observations, prepare-before-apply and
readback-only recovery. The fixture is not a privileged Rust daemon, actual
OS authentication, or a cryptographic receipt. #27 must implement the trusted
owner with real authorization, exclusive cross-process fencing and bounded
same-daemon captures; #20 still owns authenticated client address binding.
No UI or PacketTunnel live caller and no second device enabled.

### Versioned public enrollment receipt candidate (#20)

An explicit request UUID is part of the trusted owner's exact enrollment
intent. Only a committed settlement followed by an exact durable journal
readback under the same lease returns a public receipt candidate. It binds
request and plan UUIDs, server and client keys, roster epoch, committed
revision and allocated slot; host routes are derived from that slot.
A rollback, mismatched record, noncanonical/oversized payload, stale request
context or reserved UUID does not yield an accepted candidate. Recovery only
returns settlement, never a receipt reconstructed from a new request ID.
The current journal does NOT persist the request ID or receipt, so receipt
loss/restart requires a future durable request/receipt replay protocol; do not
retry enrollment blindly. Canonical encoding and context comparison do not
authenticate bytes (including slot). The future authenticated control channel
must verify the entire exact receipt, independently establish expected
context including the exact slot and atomically consume its request ID before native binding. No
secret, QR receipt import, profile write, dynamic tunnel slot, signing with a
WireGuard key or live daemon owner is introduced.

### Rust administrative request policy (#27 / #20)

The dependency-free `macos/PeerOwnerPolicy` crate independently validates a
fixed 129-byte public request and exact server/generation/epoch/revision,
canonical unique roster, lowest free enrollment slot and exact key/slot
revocation. It cannot express global peer replacement, arbitrary routes or
secret-bearing commands. This is structural policy only, not a privileged
owner, authenticated transport, private BoringTun socket patch or durable
replay/fence. See the crate README for the wire layout and remaining gates.

### Durable enrollment request recovery (#20)

V1 public journal records remain readable with their exact original encoding.
The first explicit enrollment prepares a V2 record that atomically reserves
the request UUID alongside the pending plan. Committed settlement stores the
latest public receipt in the same journal replacement; rollback retains the
request tombstone but no receipt. Recovery settles the original durable plan
without a second apply, and the exact original authorized request may replay
only the latest unchanged receipt after fresh fenced inventory and exact journal
readback. Later preparation invalidates the previous receipt; changed context,
revocation, pending state and used IDs cannot authorize another dispatch.
The bounded 512-ID ledger never evicts in an epoch; exhaustion refuses explicit
enrollment, including after restart. A future reviewed epoch migration/retention
policy is required for longer operation. V1 has no historic request IDs and
cannot reconstruct pre-upgrade receipts (no live enrollment was enabled).
This local trusted journal is not channel authentication, anti-rollback storage,
client-side receipt consumption, or a real daemon fence. No UI or native profile
activation is enabled.

### Bounded Rust local request ingress (#27)

The Rust policy crate now reads one owned Unix stream using a fixed buffer
and an absolute deadline across all fragments and mandatory write-half EOF.
Truncated, overlong, malformed and stalled streams fail closed; no listener,
privileged socket path, OS credential authorization or response protocol is
introduced. Success retains the same connection for future response delivery;
admission and caller authentication must precede invocation.

### Rust single-owner mutation gate (#27)

The Rust owner policy has an in-process exclusive lease state machine for
exact prepared plan, one dispatch, terminal before/after inventory and
revision-incremented durable settlement. Ambiguous release or mismatched
readback quarantines without reset. This is a trusted adapter contract, not
a live BoringTun mutation or proof of cross-process exclusion, disk sync,
OS authorization, or restart recovery. No new privileged caller is wired.

### macOS connected peer authentication (#27)

The Rust owner contract now queries effective UID/GID using Darwin
`getpeereid` on the same connected UnixStream and requires an independently
approved exact request with a bounded lifetime before acquisition. A private
nonserializable authorized value is consumed by the public lease gate.
Other platforms fail closed; Linux exercises that rejection and macOS CI
exercises real socketpair credentials. This does not establish application
code identity, user presence, remote identity, real approval issuance,
listener admission, durable replay or the live BoringTun adapter.

### Swift/Rust owner request encoding (#20 / #27)

A public Swift encoder now matches the Rust 129-byte v1 frame; shared golden
vectors verify UUID ordering, unsigned big-endian revisions, keys and exact
operation/slot on both sides. This does not authorize the request or connect
the companion to the daemon. Native client address receipt binding remains
separate.

### Signed client enrollment receipt and one-shot Keychain claim (#20)

The client-side CryptoKit Ed25519 verifier requires an independently trusted
control-plane signing pin, exact expected request/transaction/server/client/
epoch/revision/slot context, canonical receipt bytes and a domain-separated
64-byte signature. WireGuard X25519 keys are not signing pins. An opaque
verified value may be claimed once using device-only nonsynchronizable
SecItemAdd, keyed by request UUID; duplicate, conflicting, missing readback
or ambiguous write refuses another claim. The wrapper checks current client
identity, matching existing server profile, and absence of PSK/rotation
conflicts before/after claim. No native profile write or VPN activation is
performed. The actual independent pin ceremony, signer/transport, durable
cross-store recovery, replay retention/epoch migration and anti-rollback
assumptions remain open. No live caller or signing private key is added.

### Independently confirmed enrollment signing pin (#20)

The public pin policy computes a full domain-separated SHA-256 fingerprint
of exact server WireGuard, client WireGuard and separate Ed25519 signer keys.
Confirmation requires the full independently compared lowercase hex digest;
a canonical device-only nonsynchronizable Keychain record is inserted once
per server and binds the active client, with no automatic pin replacement.
Receipt verification loads the stored pin; the one-shot claim rechecks that
pin and current local state before and after insertion. No actual trusted Mac
signer, independent display or UI ceremony is wired. The user must obtain
fingerprint from a trusted separate display; supplying the same value from
an incoming message is not authentication. No automatic signer rotation or
re-pair with changed identity, no profile activation. Recovery and actual
signed transport remain outstanding.

### Mac-only enrollment signing identity custody (#20/#27)

Explicit first-time commissioning generates a separate Ed25519 seed, binds its public identity to the verified WireGuard server, persists a canonical record via insert-only non-synchronizable data-protection Keychain and returns only the exact winner's public identity. Established lookup requires an independently retained expected signing public key and is read-only; missing, corrupt, replaced or wrong-server record fails closed. Never call commissioning as recovery. Mac data-protection Keychain requires appropriate signed access; no legacy fallback, no iOS App Group, no UI or live daemon caller, no arbitrary signing operation. Trusted server readback and first-commission authorization are future owner contracts; this does not prove daemon custody, process exclusion, user presence, anti-rollback or real signed Keychain access. Native macOS smoke executes actual CryptoKit with injected persistence faults, not physical Keychain acceptance. Do not enable signer or peer activation until authenticated owner and storage ownership are established.
