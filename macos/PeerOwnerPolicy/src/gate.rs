//! Single-owner in-process transaction gate for the future Rust daemon.
//! All methods must be called by a trusted adapter after real OS authorization
//! and while excluding alternate writers. Structs are not network capabilities.
//! Durable proof inputs are readbacks supplied by the trusted journal adapter;
//! they are not proof of disk writes or daemon fencing by themselves.
//! This module deliberately does not open BoringTun, sockets or a journal.

use super::{nonzero, Id, PeerDelta, PublicRoster, UntrustedRequest};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateError {
    Busy, Quarantined, WrongLease, WrongPhase, InvalidPlan, InvalidEvidence, Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution { Committed, RolledBack }

/// Local, non-serializable handle; only the one trusted owner instance can
/// issue it. The adapter must generate a fresh generation on every restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    generation: Id,
    serial: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Plan {
    request: UntrustedRequest,
    before: PublicRoster,
    after: PublicRoster,
    delta: PeerDelta,
}

impl Plan {
    pub fn request(&self) -> &UntrustedRequest { &self.request }
    pub fn before(&self) -> &PublicRoster { &self.before }
    pub fn after(&self) -> &PublicRoster { &self.after }
    pub fn delta(&self) -> PeerDelta { self.delta }
}

/// Only trusted durable journal readback may supply this value. The gate
/// verifies exact plan equality, not whether the adapter actually synced disk.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedReadback {
    pub transaction: Id,
    pub plan: Plan,
}

/// Trusted adapter must have fenced ALL writes for this exact transaction
/// before capturing the terminal roster. This type is not a fence primitive.
pub struct TerminalReadback {
    pub transaction: Id,
    pub inventory: PublicRoster,
}

/// Exact durable journal readback after atomic settlement.
pub struct SettledReadback {
    pub transaction: Id,
    pub request_id: Id,
    pub resolution: Resolution,
    pub current: PublicRoster,
}

enum Phase {
    Acquired,
    Prepared(Id),
    Dispatched(Id),
    Terminal(Id, Resolution, PublicRoster),
    Settled,
}

struct Active {
    lease: Lease,
    plan: Plan,
    phase: Phase,
}

enum State {
    Idle,
    Active(Box<Active>),
    Quarantined,
}

/// One instance per verified daemon generation. An exclusive mutable borrow
/// serializes operations inside the process; no Clone or reset API. Drop or
/// restart is NOT a fence: the future startup adapter must recover pending
/// durable work and prove containment before constructing a fresh gate.
pub struct OwnerGate {
    generation: Id,
    serial: u64,
    state: State,
}

impl OwnerGate {
    /// Only construct after startup reconciliation and verified exclusion of
    /// alternate writers. No authentication is performed by this constructor.
    pub fn new(generation: Id) -> Result<Self, GateError> {
        if !nonzero(&generation) { return Err(GateError::InvalidPlan); }
        Ok(Self { generation, serial: 0, state: State::Idle })
    }

    /// Invoke only for an OS-authenticated caller authorized for exact request.
    /// The trusted adapter supplies a complete fresh verified roster.
    pub fn acquire(&mut self, request: UntrustedRequest, before: PublicRoster)
        -> Result<(Lease, Plan), GateError>
    {
        match self.state {
            State::Idle => {},
            State::Quarantined => return Err(GateError::Quarantined),
            State::Active(_) => return Err(GateError::Busy),
        }
        if request.generation() != self.generation {
            return Err(GateError::InvalidPlan);
        }
        let delta = before.propose(&request).map_err(|_| GateError::InvalidPlan)?;
        let mut after = before.clone();
        match delta {
            PeerDelta::Enroll(peer) => {
                after.peers.push(peer);
                after.peers.sort_by_key(|peer| peer.slot());
            }
            PeerDelta::Revoke(peer) => after.peers.retain(|p| *p != peer),
        }
        // Both daemon observations are at the pre-settlement journal revision.
        // Only durable settlement advances the journal revision.
        let plan = Plan { request, before, after, delta };
        self.serial = self.serial.checked_add(1).ok_or(GateError::Exhausted)?;
        let lease = Lease { generation: self.generation, serial: self.serial };
        self.state = State::Active(Box::new(Active { lease, plan: plan.clone(), phase: Phase::Acquired }));
        Ok((lease, plan))
    }

    fn active(&mut self, lease: Lease) -> Result<&mut Active, GateError> {
        match &mut self.state {
            State::Active(active) if active.lease == lease => Ok(active),
            State::Quarantined => Err(GateError::Quarantined),
            _ => Err(GateError::WrongLease),
        }
    }

    /// The adapter must call after durable prepare. An ambiguous/mismatched
    /// prepare readback must quarantine, because disk might contain pending work.
    pub fn prepared(&mut self, lease: Lease, evidence: PreparedReadback) -> Result<(), GateError> {
        let active = self.active(lease)?;
        if !matches!(active.phase, Phase::Acquired) { return Err(GateError::WrongPhase); }
        if !nonzero(&evidence.transaction) || evidence.plan != active.plan {
            self.state = State::Quarantined;
            return Err(GateError::InvalidEvidence);
        }
        active.phase = Phase::Prepared(evidence.transaction);
        Ok(())
    }

    /// Marks dispatch BEFORE returning the single exact delta. An apply error
    /// or cancellation cannot make this method return the delta a second time.
    pub fn take_dispatch(&mut self, lease: Lease, transaction: Id) -> Result<PeerDelta, GateError> {
        let active = self.active(lease)?;
        match active.phase {
            Phase::Prepared(id) if id == transaction => {
                active.phase = Phase::Dispatched(id);
                Ok(active.plan.delta)
            }
            _ => Err(GateError::WrongPhase),
        }
    }

    /// Only after the real adapter establishes terminal fencing; no callback
    /// can substitute a wrong transaction or different public roster.
    /// A prepared but undispatched transaction can only roll back.
    pub fn terminal(&mut self, lease: Lease, evidence: TerminalReadback) -> Result<Resolution, GateError> {
        let active = self.active(lease)?;
        let (id, dispatched) = match active.phase {
            Phase::Prepared(id) => (id, false),
            Phase::Dispatched(id) => (id, true),
            _ => return Err(GateError::WrongPhase),
        };
        let resolution = if evidence.transaction != id {
            None
        } else if evidence.inventory == active.plan.before {
            Some(Resolution::RolledBack)
        } else if dispatched && evidence.inventory == active.plan.after {
            Some(Resolution::Committed)
        } else {
            None
        };
        let Some(resolution) = resolution else {
            self.state = State::Quarantined;
            return Err(GateError::InvalidEvidence);
        };
        let mut expected = evidence.inventory;
        expected.revision += 1; // request/proposal already rejects u64::MAX
        active.phase = Phase::Terminal(id, resolution, expected);
        Ok(resolution)
    }

    /// A terminal observation alone cannot release the writer lease.
    /// Require exact durable settlement readback, including revision bump.
    pub fn settled(&mut self, lease: Lease, evidence: SettledReadback) -> Result<(), GateError> {
        let active = self.active(lease)?;
        let Phase::Terminal(id, resolution, expected) = &active.phase else {
            return Err(GateError::WrongPhase);
        };
        if evidence.transaction != *id || evidence.request_id != active.plan.request.request_id()
            || evidence.resolution != *resolution || evidence.current != *expected
        {
            self.state = State::Quarantined;
            return Err(GateError::InvalidEvidence);
        }
        active.phase = Phase::Settled;
        Ok(())
    }

    /// Call on any ambiguous I/O/fence failure, including ambiguous prepare
    /// before acknowledgement. No in-process reset: require external recovery.
    pub fn quarantine(&mut self, lease: Lease) -> Result<(), GateError> {
        self.active(lease)?;
        self.state = State::Quarantined;
        Ok(())
    }

    /// A failed/canceled lease must not silently become available after prepare.
    /// Acquired-only release is safe ONLY if no prepare attempt was made or
    /// the adapter has proven it had no durable side effect; otherwise quarantine.
    pub fn release(&mut self, lease: Lease) -> Result<(), GateError> {
        let active = self.active(lease)?;
        if !matches!(active.phase, Phase::Acquired | Phase::Settled) {
            self.state = State::Quarantined;
            return Err(GateError::Quarantined);
        }
        self.state = State::Idle;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Peer, FRAME_LEN};

    fn request() -> UntrustedRequest {
        let mut frame = [0; FRAME_LEN];
        frame[..4].copy_from_slice(b"SAPO");
        frame[4] = 1;
        frame[5] = 1;
        frame[8..24].fill(1);
        frame[24..40].fill(2);
        frame[40..56].fill(3);
        frame[56..64].copy_from_slice(&7u64.to_be_bytes());
        frame[64..96].fill(42);
        frame[96..128].fill(9);
        UntrustedRequest::decode(&frame).unwrap()
    }

    fn before() -> PublicRoster {
        PublicRoster::new([42; 32], [2; 16], [3; 16], 7,
            vec![Peer::new([8; 32], 2).unwrap()]).unwrap()
    }

    fn acquire(gate: &mut OwnerGate) -> (Lease, Plan) {
        gate.acquire(request(), before()).unwrap()
    }

    fn prepare(gate: &mut OwnerGate, lease: Lease, plan: &Plan) {
        gate.prepared(lease, PreparedReadback { transaction: [4; 16], plan: plan.clone() }).unwrap();
    }

    fn finish(gate: &mut OwnerGate, lease: Lease, plan: &Plan, resolution: Resolution) {
        let mut roster = if resolution == Resolution::Committed { plan.after.clone() } else { plan.before.clone() };
        roster.revision += 1;
        gate.settled(lease, SettledReadback {
            transaction: [4; 16], request_id: request().request_id(), resolution, current: roster,
        }).unwrap();
        gate.release(lease).unwrap();
    }

    #[test]
    fn committed_path_holds_lease_until_exact_durable_settlement() {
        let mut gate = OwnerGate::new([2; 16]).unwrap();
        let (lease, plan) = acquire(&mut gate);
        assert!(matches!(gate.acquire(request(), before()), Err(GateError::Busy)));
        assert!(matches!(gate.take_dispatch(lease, [4; 16]), Err(GateError::WrongPhase)));
        prepare(&mut gate, lease, &plan);
        assert!(matches!(gate.take_dispatch(lease, [5; 16]), Err(GateError::WrongPhase)));
        assert!(gate.take_dispatch(lease, [4; 16]).unwrap() == plan.delta());
        assert!(matches!(gate.take_dispatch(lease, [4; 16]), Err(GateError::WrongPhase)));
        assert_eq!(gate.terminal(lease, TerminalReadback {
            transaction: [4; 16], inventory: plan.after.clone(),
        }).unwrap(), Resolution::Committed);
        assert!(matches!(gate.acquire(request(), before()), Err(GateError::Busy)));
        finish(&mut gate, lease, &plan, Resolution::Committed);
        let (next, _) = acquire(&mut gate);
        assert_ne!(next, lease);
        assert_eq!(gate.release(lease), Err(GateError::WrongLease));
        gate.release(next).unwrap();
    }

    #[test]
    fn prepared_cancellation_requires_terminal_rollback_and_revision_bump() {
        let mut gate = OwnerGate::new([2; 16]).unwrap();
        let (lease, plan) = acquire(&mut gate);
        prepare(&mut gate, lease, &plan);
        assert_eq!(gate.terminal(lease, TerminalReadback {
            transaction: [4; 16], inventory: plan.before.clone(),
        }).unwrap(), Resolution::RolledBack);
        finish(&mut gate, lease, &plan, Resolution::RolledBack);
    }

    #[test]
    fn ambiguous_release_and_explicit_quarantine_block_new_work() {
        for stage in 0..4 {
            let mut gate = OwnerGate::new([2; 16]).unwrap();
            let (lease, plan) = acquire(&mut gate);
            if stage == 0 {
                gate.quarantine(lease).unwrap();
            } else {
                prepare(&mut gate, lease, &plan);
                if stage >= 2 { gate.take_dispatch(lease, [4; 16]).unwrap(); }
                if stage == 3 {
                    gate.terminal(lease, TerminalReadback {
                        transaction: [4; 16], inventory: plan.after.clone(),
                    }).unwrap();
                }
                assert_eq!(gate.release(lease), Err(GateError::Quarantined));
            }
            assert!(matches!(gate.acquire(request(), before()), Err(GateError::Quarantined)));
        }
    }

    #[test]
    fn wrong_or_undispatched_terminal_evidence_quarantines() {
        for mode in 0..4 {
            let mut gate = OwnerGate::new([2; 16]).unwrap();
            let (lease, plan) = acquire(&mut gate);
            prepare(&mut gate, lease, &plan);
            if mode != 0 { gate.take_dispatch(lease, [4; 16]).unwrap(); }
            let mut observed = plan.after.clone();
            if mode == 2 { observed.generation = [7; 16]; }
            if mode == 3 { observed.peers.clear(); }
            let id = if mode == 1 { [5; 16] } else { [4; 16] };
            assert_eq!(gate.terminal(lease, TerminalReadback { transaction: id, inventory: observed }),
                Err(GateError::InvalidEvidence));
            assert!(matches!(gate.acquire(request(), before()), Err(GateError::Quarantined)));
        }
    }

    #[test]
    fn stale_or_wrong_durable_settlement_quarantines() {
        for mode in 0..4 {
            let mut gate = OwnerGate::new([2; 16]).unwrap();
            let (lease, plan) = acquire(&mut gate);
            prepare(&mut gate, lease, &plan);
            gate.take_dispatch(lease, [4; 16]).unwrap();
            gate.terminal(lease, TerminalReadback {
                transaction: [4; 16], inventory: plan.after.clone(),
            }).unwrap();
            let mut roster = plan.after.clone();
            if mode != 0 { roster.revision += 1; }
            let result = gate.settled(lease, SettledReadback {
                transaction: if mode == 1 { [5; 16] } else { [4; 16] },
                request_id: if mode == 2 { [5; 16] } else { request().request_id() },
                resolution: if mode == 3 { Resolution::RolledBack } else { Resolution::Committed },
                current: roster,
            });
            assert_eq!(result, Err(GateError::InvalidEvidence));
            assert!(matches!(gate.acquire(request(), before()), Err(GateError::Quarantined)));
        }
    }

    #[test]
    fn wrong_prepare_or_generation_refused() {
        let mut wrong = OwnerGate::new([7; 16]).unwrap();
        assert!(matches!(wrong.acquire(request(), before()), Err(GateError::InvalidPlan)));
        let mut gate = OwnerGate::new([2; 16]).unwrap();
        let (lease, mut plan) = acquire(&mut gate);
        plan.after.peers.clear();
        assert_eq!(gate.prepared(lease, PreparedReadback { transaction: [4; 16], plan }),
            Err(GateError::InvalidEvidence));
        assert!(matches!(gate.acquire(request(), before()), Err(GateError::Quarantined)));
    }
}
