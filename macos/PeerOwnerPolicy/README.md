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

## macOS connected peer credential gate

`local_auth` queries Darwin `getpeereid` on the original owned UnixStream
before reading and after exact bounded frame decoding. The effective UID/GID
must match a one-use, nonserializable, expiring trusted approval of the entire
request. The public OwnerGate acquisition consumes the authorized connection,
not an untrusted frame. Unsupported platforms fail closed. The tiny Darwin
FFI is the only allowed unsafe boundary; no new dependency or Go backend.
This is OS account authentication, not app code identity, user presence or
remote iPhone authentication. Trusted approval issuance, durable replay,
listener admission limits, authenticated response, daemon fencing and live
BoringTun mutation remain unimplemented. The grant constructor is trusted
in-process only; never mint a grant from incoming client fields.

The native test compares connected peer IDs with real process effective IDs;
invalid budgets and expired approval are refused before reading. Same-UID
request substitution tests include operation, request/generation/epoch IDs,
revision and both keys. A trusted grant issuer must prevent duplicate grants
and protect approval from other processes running under the same account.

## Swift/Rust wire compatibility

The Swift companion-side encoder emits the exact v1 public frame with explicit
UUID tuple byte order and unsigned big-endian revision. Linux Swift and the
Rust decoder consume the same two golden vectors in Tests/build; native
XCTest checks the same literal vectors and invalid inputs. No UI, socket
caller, privileged grant issuance or mutation is wired to the encoder.
