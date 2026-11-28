# Rust peer-owner administrative boundary

This dependency-free crate is a source-only policy for issue #27 and #20,
not a daemon, socket server, authentication scheme, or WireGuard engine.
BoringTun remains the pinned WireGuard engine. The private Mac adapter must
authenticate the local caller at the OS boundary and authorize the exact
request before obtaining an exclusive lease. Never expose raw UAPI.

Fixed binary v1 frame (129 bytes; all IDs are 16 raw bytes, keys 32 raw
public bytes, revision unsigned big endian):

| Offset | Length | Field |
|---|---:|---|
| 0 | 4 | SAPO magic |
| 4 | 1 | Version 1 |
| 5 | 1 | 1=enroll, 2=revoke |
| 6 | 2 | Reserved zero |
| 8 | 16 | Request ID |
| 24 | 16 | Daemon generation |
| 40 | 16 | Roster epoch |
| 56 | 8 | Expected revision |
| 64 | 32 | Server public key |
| 96 | 32 | Client public key |
| 128 | 1 | Zero for enroll, exact slot for revoke |

Decoder is bounded and produces an untrusted value. PublicRoster is an
independently checked structural projection of a future authoritative,
complete capture; it must be supplied by the trusted daemon owner, not
the request. No private key, PSK, arbitrary route, endpoint, shell
command or broad replace-peers operation is representable. No key
representation check proves possession or contributory behavior.

The next integration must implement bounded framed IPC, peer credential
and explicit authorization, request replay persistence, real Rust daemon
generation/fencing, a durable prepared journal and terminal readback.
Do not route requests from AgentMac or PacketTunnel yet. Do not enable
live enrollment or revocation. Swift/Rust shared golden vectors and
authenticated cross-process tests remain future integration acceptance.

Tests: cargo +1.90.0 test --locked --offline --manifest-path macos/PeerOwnerPolicy/Cargo.toml

## Bounded local request ingress

`stream::read_single_request` owns a connected UnixStream and reads exactly
129 bytes plus EOF under one absolute budget (0 < budget <= 5 seconds).
Truncation, extra bytes, deadline, malformed frame and I/O error are refused.
Errors close the stream; success returns the same owned connection for a
future bounded authenticated response. No listener is added.
Caller must authenticate OS peer credentials and authorize the exact request,
limit concurrent admissions, and design response delivery before live use.
Five local socket-pair tests run in existing Linux/macOS Rust CI.

## Exclusive owner transaction gate

`gate::OwnerGate` implements a non-cloneable, single-generation state machine
for one trusted owner instance. Its local lease binds the exact request and
before/after roster, marks preparation before any write, accepts exact durable prepare readback, returns the
single delta only once, requires same-transaction terminal inventory, and
holds the lease until exact durable settlement with a revision increment.
Ambiguous preparation, release or mismatched terminal/settlement readback
quarantines the gate; no reset API. Seven regression tests exercise ordering,
wrong generation/transaction, cancellation, stale lease and quarantine.
The trusted adapter still owes real OS authorization, process exclusivity,
fencing, journal proof, replay persistence and startup reconciliation;
constructing a new instance does not prove any of those properties.
