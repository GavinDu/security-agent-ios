# Peer-bound optional WireGuard PSK (#21)

The transport previously used one global optional Keychain PSK for any
selected server. It now selects only a canonical versioned device-local
record bound to the exact server public key and the public key derived
from the same private identity that will enter the Rust BoringTun codec.

No secret is written to QR, public profile, App Group, roster or logs.
A malformed, mismatched or explicit zero PSK stops startup. A present
legacy global PSK also stops startup, rather than silently reusing it or
downgrading to a no-PSK handshake. No automatic migration or deletion is
performed: the existing secret may belong to an unknown peer. Devices
without any PSK record retain optional no-PSK WireGuard operation.

This is selection safety, not provisioning. No app writer is added.
The authenticated channel, bilateral staged commit, explicit migration,
required-PSK marker bound to the committed profile, recovery and actual
mismatch/handshake acceptance are still #21. In particular absence of
both records is not proof that a previously provisioned PSK was never
deleted; a required-PSK marker is necessary before enabling provisioning.
