# Local identity rotation staging (#22)

The active shared Keychain identity remains immutable. A future authenticated
rotation owner can stage one separate candidate in the device-only Keychain
account, bound to the transaction ID, verified Mac public key and current
client public key. The policy re-derives the candidate public key from stored
private bytes and refuses same-identity or server-key candidates. Insert-only
storage and readback adopt the winner of a same-binding retry; a different
binding, malformed record, missing winner or changed active identity blocks.

The receipt contains only public identity metadata. Do not encode the private
stage record into QR, App Group, native profile, logs or roster journal.

This is local staging infrastructure only, not an authenticated exchange,
a live rotation, or an activation/recovery protocol. No UI or PacketTunnel
caller uses it. The future rotation owner must authenticate the Mac,
serialize active-identity changes across processes, track dispatch and
terminal daemon fencing, prove the replacement handshake and only then
commit/revoke, with explicit cancellation and crash cleanup of the stage.
Do not enable rotation before these gates are implemented and verified.

## Read-only restart recovery and PSK exclusion

Recovery of an exact transaction re-derives the public candidate from its
stored private key, verifies the canonical record and checks the active
identity before and after reading. An absent or corrupt stage fails closed;
recovery never generates a new candidate or mutates Keychain. The reserved
all-zero transaction UUID is rejected before accessing the store. Both local
entrypoints require the same-server unmarked public profile and no legacy,
committed or staged PSK; PSK-protected rotation is not yet supported. Local
checks alone do not prove native preference binding or atomic exclusion of
other processes. The future authenticated owner must supply those guarantees,
including an exact daemon/handshake receipt and a crash-safe activation and
revocation protocol. No activation path is added.
