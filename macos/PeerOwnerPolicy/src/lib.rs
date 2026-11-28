#![forbid(unsafe_code)]

//! Pure Rust administrative request/plan validation for the future private
//! BoringTun macOS owner. No sockets, shell commands, secrets, OS credential
//! checks, durable journal, or live peer mutation. A decoded request is
//! UNTRUSTED: authorization and exclusive daemon fencing must precede use.
//! These types are not capabilities and must never be exposed as an open RPC.

use std::collections::HashSet;

#[cfg(unix)]
pub mod stream;

pub const FRAME_LEN: usize = 129;
const MAGIC: &[u8; 4] = b"SAPO";
const VERSION: u8 = 1;
pub const MAX_PEERS: usize = 253;
type Id = [u8; 16];
type PublicKey = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidFrame,
    InvalidRoster,
    WrongContext,
    DuplicatePeer,
    NoSlot,
    MissingExactPeer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Enroll,
    Revoke { slot: u8 },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UntrustedRequest {
    request_id: Id,
    generation: Id,
    epoch: Id,
    revision: u64,
    server: PublicKey,
    client: PublicKey,
    operation: Operation,
}

fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

fn valid_slot(slot: u8) -> bool {
    (2..=254).contains(&slot)
}

impl UntrustedRequest {
    /// Exact fixed frame: magic(4), version(1), op(1), reserved(2),
    /// request ID(16), daemon generation(16), roster epoch(16),
    /// big-endian revision(8), server key(32), client key(32), slot(1).
    /// There is no variable-length field, command string or secret field.
    /// Caller must separately bound socket reads and authenticate the caller.
    pub fn decode(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() != FRAME_LEN || &frame[..4] != MAGIC
            || frame[4] != VERSION || frame[6..8] != [0, 0]
        {
            return Err(Error::InvalidFrame);
        }
        let operation = match (frame[5], frame[128]) {
            (1, 0) => Operation::Enroll,
            (2, slot) if valid_slot(slot) => Operation::Revoke { slot },
            _ => return Err(Error::InvalidFrame),
        };
        let request_id: Id = frame[8..24].try_into().map_err(|_| Error::InvalidFrame)?;
        let generation: Id = frame[24..40].try_into().map_err(|_| Error::InvalidFrame)?;
        let epoch: Id = frame[40..56].try_into().map_err(|_| Error::InvalidFrame)?;
        let revision = u64::from_be_bytes(frame[56..64].try_into().map_err(|_| Error::InvalidFrame)?);
        let server: PublicKey = frame[64..96].try_into().map_err(|_| Error::InvalidFrame)?;
        let client: PublicKey = frame[96..128].try_into().map_err(|_| Error::InvalidFrame)?;
        if !nonzero(&request_id) || !nonzero(&generation) || !nonzero(&epoch)
            || !nonzero(&server) || !nonzero(&client) || server == client
            || revision == u64::MAX
        {
            return Err(Error::InvalidFrame);
        }
        Ok(Self { request_id, generation, epoch, revision, server, client, operation })
    }

    pub fn request_id(&self) -> Id { self.request_id }
    pub fn operation(&self) -> Operation { self.operation }
    pub fn server(&self) -> PublicKey { self.server }
    pub fn client(&self) -> PublicKey { self.client }
    pub fn generation(&self) -> Id { self.generation }
    pub fn epoch(&self) -> Id { self.epoch }
    pub fn revision(&self) -> u64 { self.revision }
}

/// Public peer projection only. Keys have representation checks, not X25519
/// contributory validation; use the pinned WireGuard engine for handshakes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    key: PublicKey,
    slot: u8,
}

impl Peer {
    pub fn new(key: PublicKey, slot: u8) -> Result<Self, Error> {
        if !nonzero(&key) || !valid_slot(slot) {
            return Err(Error::InvalidRoster);
        }
        Ok(Self { key, slot })
    }
    pub fn key(&self) -> PublicKey { self.key }
    pub fn slot(&self) -> u8 { self.slot }
    pub fn host_routes(&self) -> (String, String) {
        (format!("10.8.0.{}/32", self.slot), format!("fd86:ea04:1111::{:x}/128", self.slot))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicRoster {
    server: PublicKey,
    generation: Id,
    epoch: Id,
    revision: u64,
    peers: Vec<Peer>,
}

impl PublicRoster {
    /// Requires an already complete public-only capture under the trusted
    /// owner's exclusive lease. This constructor only checks structure.
    pub fn new(server: PublicKey, generation: Id, epoch: Id, revision: u64,
               peers: Vec<Peer>) -> Result<Self, Error> {
        if !nonzero(&server) || !nonzero(&generation) || !nonzero(&epoch)
            || peers.len() > MAX_PEERS
        {
            return Err(Error::InvalidRoster);
        }
        let mut keys = HashSet::with_capacity(peers.len());
        let mut last_slot = 1;
        for peer in &peers {
            if peer.key == server || !nonzero(&peer.key) || !valid_slot(peer.slot)
                || peer.slot <= last_slot || !keys.insert(peer.key)
            {
                return Err(Error::InvalidRoster);
            }
            last_slot = peer.slot;
        }
        Ok(Self { server, generation, epoch, revision, peers })
    }

    /// Validate exactly one public delta. Enrollment cannot specify a slot:
    /// choose the same lowest free slot as the Swift policy. Revocation must
    /// match both key and slot. No replacement of the entire peer roster.
    /// This is only a proposal; never dispatch without OS authorization,
    /// durable prepare, a real exclusive lease and terminal fencing.
    pub fn propose(&self, request: &UntrustedRequest) -> Result<PeerDelta, Error> {
        if request.server != self.server || request.generation != self.generation
            || request.epoch != self.epoch || request.revision != self.revision
            || self.revision == u64::MAX
        {
            return Err(Error::WrongContext);
        }
        match request.operation {
            Operation::Enroll => {
                if self.peers.iter().any(|peer| peer.key == request.client) {
                    return Err(Error::DuplicatePeer);
                }
                let slot = (2..=254).find(|slot| !self.peers.iter().any(|peer| peer.slot == *slot))
                    .ok_or(Error::NoSlot)?;
                Ok(PeerDelta::Enroll(Peer::new(request.client, slot)?))
            }
            Operation::Revoke { slot } => {
                let peer = self.peers.iter().find(|peer| peer.key == request.client && peer.slot == slot)
                    .ok_or(Error::MissingExactPeer)?;
                Ok(PeerDelta::Revoke(*peer))
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PeerDelta {
    Enroll(Peer),
    Revoke(Peer),
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(op: u8, slot: u8) -> [u8; FRAME_LEN] {
        let mut bytes = [0; FRAME_LEN];
        bytes[..4].copy_from_slice(MAGIC);
        bytes[4] = VERSION;
        bytes[5] = op;
        bytes[8..24].fill(1);
        bytes[24..40].fill(2);
        bytes[40..56].fill(3);
        bytes[56..64].copy_from_slice(&7u64.to_be_bytes());
        bytes[64..96].fill(42);
        bytes[96..128].fill(9);
        bytes[128] = slot;
        bytes
    }
    fn roster(peers: Vec<Peer>) -> PublicRoster {
        PublicRoster::new([42; 32], [2; 16], [3; 16], 7, peers).unwrap()
    }
    fn peer(key: u8, slot: u8) -> Peer { Peer::new([key; 32], slot).unwrap() }

    #[test]
    fn exact_frame_rejects_all_truncations_and_trailing_bytes() {
        let bytes = frame(1, 0);
        let request = UntrustedRequest::decode(&bytes).unwrap();
        assert_eq!(request.operation(), Operation::Enroll);
        assert_eq!(request.request_id(), [1; 16]);
        assert_eq!(request.revision(), 7);
        for n in 0..FRAME_LEN {
            assert!(matches!(UntrustedRequest::decode(&bytes[..n]), Err(Error::InvalidFrame)));
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(UntrustedRequest::decode(&trailing).is_err());
    }

    #[test]
    fn rejects_wrong_version_reserved_fields_and_unpermitted_operations() {
        for (offset, value) in [(0, 0), (4, 2), (5, 3), (6, 1), (7, 1), (128, 2)] {
            let mut bytes = frame(1, 0);
            bytes[offset] = value;
            assert!(UntrustedRequest::decode(&bytes).is_err());
        }
        for slot in [0, 1, 255] {
            assert!(UntrustedRequest::decode(&frame(2, slot)).is_err());
        }
    }

    #[test]
    fn rejects_zero_ids_keys_self_peer_and_overflow() {
        for (start, end) in [(8, 24), (24, 40), (40, 56), (64, 96), (96, 128)] {
            let mut bytes = frame(1, 0);
            bytes[start..end].fill(0);
            assert!(UntrustedRequest::decode(&bytes).is_err());
        }
        let mut bytes = frame(1, 0);
        bytes[96..128].fill(42);
        assert!(UntrustedRequest::decode(&bytes).is_err());
        let mut bytes = frame(1, 0);
        bytes[56..64].fill(255);
        assert!(UntrustedRequest::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_wrong_generation_epoch_revision_and_server() {
        let current = roster(vec![]);
        for offset in [24, 40, 63, 64] {
            let mut bytes = frame(1, 0);
            bytes[offset] ^= 1;
            let request = UntrustedRequest::decode(&bytes).unwrap();
            assert!(matches!(current.propose(&request), Err(Error::WrongContext)));
        }
    }

    #[test]
    fn lowest_free_slot_and_exact_host_routes_match_swift_contract() {
        let request = UntrustedRequest::decode(&frame(1, 0)).unwrap();
        let current = roster(vec![peer(1, 2), peer(2, 4)]);
        let PeerDelta::Enroll(candidate) = current.propose(&request).unwrap() else {
            panic!("enrollment proposal expected");
        };
        assert_eq!(candidate.slot(), 3);
        assert_eq!(candidate.key(), [9; 32]);
        assert_eq!(candidate.host_routes(), ("10.8.0.3/32".into(), "fd86:ea04:1111::3/128".into()));
        assert_eq!(peer(10, 254).host_routes(), ("10.8.0.254/32".into(), "fd86:ea04:1111::fe/128".into()));
    }

    #[test]
    fn rejects_duplicate_key_and_full_roster() {
        let request = UntrustedRequest::decode(&frame(1, 0)).unwrap();
        assert!(matches!(roster(vec![peer(9, 2)]).propose(&request), Err(Error::DuplicatePeer)));
        // Distinct synthetic public representations, excluding the server/client.
        let peers = (2..=254).map(|slot| {
            let mut key = [1; 32];
            key[0] = slot;
            Peer::new(key, slot).unwrap()
        }).collect();
        assert!(matches!(roster(peers).propose(&request), Err(Error::NoSlot)));
    }

    #[test]
    fn rejects_corrupt_or_noncanonical_roster() {
        for peers in [vec![peer(1, 2), peer(1, 3)], vec![peer(1, 2), peer(2, 2)],
                      vec![peer(1, 3), peer(2, 2)], vec![peer(42, 2)]] {
            assert!(PublicRoster::new([42; 32], [2; 16], [3; 16], 7, peers).is_err());
        }
        assert!(Peer::new([0; 32], 2).is_err());
        assert!(Peer::new([1; 32], 1).is_err());
    }

    #[test]
    fn revocation_requires_exact_key_and_slot() {
        let current = roster(vec![peer(1, 2), peer(9, 3)]);
        let wrong = UntrustedRequest::decode(&frame(2, 2)).unwrap();
        assert!(matches!(current.propose(&wrong), Err(Error::MissingExactPeer)));
        let exact = UntrustedRequest::decode(&frame(2, 3)).unwrap();
        assert!(matches!(current.propose(&exact), Ok(PeerDelta::Revoke(p)) if p == peer(9, 3)));
    }
}
