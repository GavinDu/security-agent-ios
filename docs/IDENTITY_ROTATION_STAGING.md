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
