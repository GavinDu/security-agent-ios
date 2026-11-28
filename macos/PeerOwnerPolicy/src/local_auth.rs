//! Connected-peer authentication and exact preauthorized intent for macOS.
//! getpeereid proves the peer's effective UID/GID, not code-signing identity,
//! user presence, or remote iPhone identity. The privileged owner must issue
//! grants from an independently authenticated and explicitly authorized
//! administrative channel, not from the untrusted incoming request.
//! No listener, privileged command, daemon adapter, or grant issuer is here.

use crate::{stream, UntrustedRequest};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    UnsupportedPlatform,
    CredentialUnavailable,
    WrongPeer,
    Expired,
    InvalidLifetime,
    WrongIntent,
    Frame(stream::ReadError),
}

/// A one-use, process-local approval minted only by the trusted owner.
/// It is deliberately not Clone/Copy/Decodable. Its constructor is for the
/// future trusted approval issuer, NOT a client request handler. The issuer
/// must prevent duplicate issuance and durably track request replay.
pub struct LocalGrant {
    peer: PeerIdentity,
    expected: UntrustedRequest,
    expires: Instant,
}

impl LocalGrant {
    pub fn from_trusted_approval(peer: PeerIdentity, expected: UntrustedRequest,
        lifetime: Duration) -> Result<Self, AuthError>
    {
        if lifetime.is_zero() || lifetime > Duration::from_secs(30) {
            return Err(AuthError::InvalidLifetime);
        }
        let expires = Instant::now().checked_add(lifetime).ok_or(AuthError::InvalidLifetime)?;
        Ok(Self { peer, expected, expires })
    }
}

/// Cannot be constructed from wire data. Consumed by OwnerGate; retains
/// the original connection and does not expose a raw request to callers.
pub struct AuthorizedRequest {
    request: UntrustedRequest,
    stream: UnixStream,
    expires: Instant,
}

impl AuthorizedRequest {
    pub(crate) fn into_parts(self) -> Option<(UntrustedRequest, UnixStream)> {
        if Instant::now() >= self.expires { return None; }
        Some((self.request, self.stream))
    }
}

/// Check actual OS credentials before reading any bytes, then require
/// exact approved request on the same connection and unexpired approval.
/// On failure both owned grant and stream are dropped. A matching UID/GID
/// alone never authorizes a mutation. The caller must limit admissions.
pub fn authorize(stream: UnixStream, grant: LocalGrant, budget: Duration)
    -> Result<AuthorizedRequest, AuthError>
{
    if budget.is_zero() || budget > stream::MAX_BUDGET {
        return Err(AuthError::Frame(stream::ReadError::InvalidBudget));
    }
    let remaining = grant.expires.checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero()).ok_or(AuthError::Expired)?;
    if peer_identity(&stream)? != grant.peer {
        return Err(AuthError::WrongPeer);
    }
    let (request, stream) = stream::read_single_request(stream, budget.min(remaining))
        .map_err(AuthError::Frame)?;
    if Instant::now() >= grant.expires { return Err(AuthError::Expired); }
    if request != grant.expected { return Err(AuthError::WrongIntent); }
    if peer_identity(&stream)? != grant.peer { return Err(AuthError::WrongPeer); }
    Ok(AuthorizedRequest { request, stream, expires: grant.expires })
}

#[cfg(target_os = "macos")]
fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
    darwin::peer_identity(stream)
}

#[cfg(not(target_os = "macos"))]
fn peer_identity(_: &UnixStream) -> Result<PeerIdentity, AuthError> {
    // Do not substitute a caller-supplied UID or a Linux-specific ABI.
    Err(AuthError::UnsupportedPlatform)
}

// Narrow, audited Darwin ABI boundary. uid_t and gid_t on Darwin are
// uint32_t. No borrowed pointer escapes, no ownership transfer, no errno
// disclosure. All other crate code remains under deny(unsafe_code).
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod darwin {
    use super::{AuthError, PeerIdentity};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::ffi::c_int;

    unsafe extern "C" {
        fn getpeereid(socket: c_int, euid: *mut u32, egid: *mut u32) -> c_int;
        #[cfg(test)] fn geteuid() -> u32;
        #[cfg(test)] fn getegid() -> u32;
    }

    #[cfg(test)]
    pub(super) fn current_identity() -> PeerIdentity {
        // SAFETY: these Darwin functions take no pointers and return scalar IDs.
        unsafe { PeerIdentity { uid: geteuid(), gid: getegid() } }
    }

    pub(super) fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
        let mut uid = 0u32;
        let mut gid = 0u32;
        // SAFETY: the borrowed UnixStream keeps the fd open; both pointers
        // refer to separate initialized writable Darwin uid_t/gid_t values.
        let status = unsafe { getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        if status != 0 { return Err(AuthError::CredentialUnavailable); }
        Ok(PeerIdentity { uid, gid })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FRAME_LEN;
    use std::io::Write;
    use std::net::Shutdown;

    fn frame() -> [u8; FRAME_LEN] {
        let mut bytes = [0; FRAME_LEN];
        bytes[..4].copy_from_slice(b"SAPO");
        bytes[4] = 1;
        bytes[5] = 1;
        bytes[8..24].fill(1);
        bytes[24..40].fill(2);
        bytes[40..56].fill(3);
        bytes[56..64].copy_from_slice(&7u64.to_be_bytes());
        bytes[64..96].fill(42);
        bytes[96..128].fill(9);
        bytes
    }

    fn request() -> UntrustedRequest { UntrustedRequest::decode(&frame()).unwrap() }

    #[test]
    fn invalid_lifetime_refused() {
        for lifetime in [Duration::ZERO, Duration::from_secs(31)] {
            assert!(matches!(LocalGrant::from_trusted_approval(
                PeerIdentity { uid: 1, gid: 1 }, request(), lifetime), Err(AuthError::InvalidLifetime)));
        }
    }

    #[test]
    fn expired_grant_refused_before_read() {
        let (reader, _writer) = UnixStream::pair().unwrap();
        let grant = LocalGrant { peer: PeerIdentity { uid: 1, gid: 1 },
            expected: request(), expires: Instant::now() };
        assert!(matches!(authorize(reader, grant, Duration::from_secs(1)), Err(AuthError::Expired)));
    }

    #[test]
    fn invalid_budget_never_clamped_into_valid_approval() {
        for budget in [Duration::ZERO, Duration::from_secs(6)] {
            let (reader, _writer) = UnixStream::pair().unwrap();
            let grant = LocalGrant::from_trusted_approval(PeerIdentity { uid: 1, gid: 1 },
                request(), Duration::from_secs(2)).unwrap();
            assert!(matches!(authorize(reader, grant, budget),
                Err(AuthError::Frame(stream::ReadError::InvalidBudget))));
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_platform_fails_closed() {
        let (reader, _writer) = UnixStream::pair().unwrap();
        let grant = LocalGrant::from_trusted_approval(PeerIdentity { uid: 1, gid: 1 },
            request(), Duration::from_secs(2)).unwrap();
        assert!(matches!(authorize(reader, grant, Duration::from_secs(1)), Err(AuthError::UnsupportedPlatform)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_peer_credentials_and_exact_intent_gate_acquisition() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let peer = peer_identity(&reader).unwrap();
        assert_eq!(peer, peer_identity(&writer).unwrap());
        assert_eq!(peer, darwin::current_identity());
        let grant = LocalGrant::from_trusted_approval(peer, request(), Duration::from_secs(5)).unwrap();
        writer.write_all(&frame()).unwrap();
        writer.shutdown(Shutdown::Write).unwrap();
        let authorized = authorize(reader, grant, Duration::from_secs(2)).unwrap();
        let mut gate = crate::gate::OwnerGate::new([2; 16]).unwrap();
        let before = crate::PublicRoster::new([42; 32], [2; 16], [3; 16], 7, vec![]).unwrap();
        let (lease, plan, response) = gate.acquire_authorized(authorized, before).unwrap();
        assert!(plan.request() == &request());
        assert_eq!(peer_identity(&response).unwrap(), peer);
        gate.release(lease).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn wrong_uid_or_gid_refused_before_read() {
        for wrong_uid in [true, false] {
            let (reader, _writer) = UnixStream::pair().unwrap();
            let mut peer = peer_identity(&reader).unwrap();
            if wrong_uid { peer.uid ^= 1; } else { peer.gid ^= 1; }
            let grant = LocalGrant::from_trusted_approval(peer, request(), Duration::from_secs(5)).unwrap();
            assert!(matches!(authorize(reader, grant, Duration::from_secs(2)), Err(AuthError::WrongPeer)));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn same_uid_cannot_substitute_any_request_field() {
        for offset in [5, 8, 24, 40, 63, 64, 96] {
            let (reader, mut writer) = UnixStream::pair().unwrap();
            let peer = peer_identity(&reader).unwrap();
            let grant = LocalGrant::from_trusted_approval(peer, request(), Duration::from_secs(5)).unwrap();
            let mut changed = frame();
            if offset == 5 {
                changed[5] = 2;
                changed[128] = 2;
            } else { changed[offset] ^= 1; }
            writer.write_all(&changed).unwrap();
            writer.shutdown(Shutdown::Write).unwrap();
            assert!(matches!(authorize(reader, grant, Duration::from_secs(2)), Err(AuthError::WrongIntent)));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn expired_authorized_request_cannot_acquire() {
        let (stream, _writer) = UnixStream::pair().unwrap();
        let expired = AuthorizedRequest { request: request(), stream, expires: Instant::now() };
        let mut gate = crate::gate::OwnerGate::new([2; 16]).unwrap();
        let before = crate::PublicRoster::new([42; 32], [2; 16], [3; 16], 7, vec![]).unwrap();
        assert!(matches!(gate.acquire_authorized(expired, before), Err(crate::gate::GateError::InvalidPlan)));
    }
}
