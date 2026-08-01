//! Persona lifecycle pool: select → assemble → bind transport → behavior → rotate.
//!
//! `PersonaPool` is the single owner of the full persona lifecycle (G233). A
//! caller acquires a [`PersonaSession`] for a target domain; the pool selects a
//! coherent identity, assembles the browser overrides and transport bundle,
//! binds a pacing/behavior model, and tracks the session until it is released.
//! The pool also enforces:
//!
//!   * **no mid-request rotation** (G240), a session with in-flight requests
//!     cannot be rotated;
//!   * **sticky per-domain identity** (G241/G242), repeated visits to the same
//!     domain reuse the same session;
//!   * **burned-persona quarantine** (G243/G244), a challenged/blocked persona
//!     is retired and never reassigned;
//!   * **concurrent distinct personas** (G235/G236), every active session has a
//!     unique seed and therefore a distinct identity.
//!
//! Derived values (`ProfileOverrides`, `ProfileBundle`) are cached on the
//! session to avoid rebuilding them on every request (G237). Sessions can be
//! snapshotted and restored so a warmed persona survives process restarts
//! (G238/G239).
//!
//! # Example
//!
//! ```
//! use guise::persona_pool::{PersonaPool, PoolConfig};
//!
//! let mut pool = PersonaPool::new(PoolConfig::default());
//! let id = pool.acquire("example.com").unwrap();
//! assert_eq!(pool.session(id).unwrap().in_flight(), 1);
//! pool.release(id).unwrap();
//! assert_eq!(pool.session(id).unwrap().in_flight(), 0);
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::fingerprint::identity::NavigatorProfile;
use crate::rotation::{RotationPolicy, RotationState};
use crate::sampling::RngSeed;
#[cfg(feature = "http")]
use crate::ProfileBundle;
use crate::ProfileOverrides;

#[cfg(feature = "pacing")]
use crate::pacing::RequestPacer;

#[cfg(feature = "human")]
use crate::human::timing::SessionPacing;

/// Opaque handle to a session in the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PersonaId(u64);

impl PersonaId {
    /// Expose the raw id for logging/telemetry.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PersonaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "persona:{}", self.0)
    }
}

/// A fully assembled persona session.
///
/// This is the materialized result of the lifecycle: an identity, its derived
/// browser overrides, its transport bundle, and its behavioral pacing models.
/// The session is immutable except for request/in-flight counters and the burned
/// flag, which are mutated only by the pool.
#[derive(Debug, Clone)]
pub struct PersonaSession {
    id: PersonaId,
    seed: RngSeed,
    identity: NavigatorProfile,
    overrides: ProfileOverrides,
    #[cfg(feature = "http")]
    bundle: ProfileBundle,
    request_count: u64,
    in_flight: u32,
    burned: bool,
    #[cfg(feature = "pacing")]
    request_pacer: RequestPacer,
    #[cfg(feature = "human")]
    session_pacing: SessionPacing,
}

impl PersonaSession {
    /// Opaque session handle.
    #[must_use]
    pub const fn id(&self) -> PersonaId {
        self.id
    }

    /// Seed that produced this persona; restore from this to reproduce it.
    #[must_use]
    pub const fn seed(&self) -> RngSeed {
        self.seed
    }

    /// The browser identity.
    #[must_use]
    pub fn identity(&self) -> &NavigatorProfile {
        &self.identity
    }

    /// Cached browser overrides.
    #[must_use]
    pub fn overrides(&self) -> &ProfileOverrides {
        &self.overrides
    }

    /// Cached transport bundle (browser + TLS).
    #[cfg(feature = "http")]
    #[must_use]
    pub fn bundle(&self) -> &ProfileBundle {
        &self.bundle
    }

    /// Number of requests issued through this session.
    #[must_use]
    pub const fn request_count(&self) -> u64 {
        self.request_count
    }

    /// Current in-flight request count.
    #[must_use]
    pub const fn in_flight(&self) -> u32 {
        self.in_flight
    }

    /// Whether this persona has been burned/challenged and should not be reused.
    #[must_use]
    pub const fn is_burned(&self) -> bool {
        self.burned
    }

    /// Request pacer bound to this session.
    #[cfg(feature = "pacing")]
    #[must_use]
    pub fn request_pacer(&self) -> &RequestPacer {
        &self.request_pacer
    }

    /// Behavioral session pacing bound to this session.
    #[cfg(feature = "human")]
    #[must_use]
    pub fn session_pacing(&self) -> &SessionPacing {
        &self.session_pacing
    }

    /// Mutable request pacer for status feedback.
    #[cfg(feature = "pacing")]
    #[must_use]
    pub fn request_pacer_mut(&mut self) -> &mut RequestPacer {
        &mut self.request_pacer
    }

    /// Mutable behavioral pacing.
    #[cfg(feature = "human")]
    #[must_use]
    pub fn session_pacing_mut(&mut self) -> &mut SessionPacing {
        &mut self.session_pacing
    }
}

/// Serializable snapshot of a warmed persona.
///
/// Store this to disk and restore it later; the seed reproduces the exact
/// identity and the request count preserves profile age.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersonaSnapshot {
    /// Session handle (restored verbatim if unused, otherwise reassigned).
    pub id: u64,
    /// Seed that produced the identity.
    pub seed: RngSeed,
    /// Number of requests the persona had already issued.
    pub request_count: u64,
}

/// Errors from the persona lifecycle pool.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum PoolError {
    /// The requested session is not in the pool.
    #[error("persona session {0} not found")]
    SessionNotFound(PersonaId),
    /// Rotation was requested while the session still had in-flight requests.
    #[error("cannot rotate {0}: {1} request(s) still in flight")]
    RotationInProgress(PersonaId, u32),
    /// The session has been burned and cannot be reused.
    #[error("persona session {0} has been burned")]
    Burned(PersonaId),
    /// The pool has reached its configured concurrent-session limit.
    #[error("persona pool at capacity: {0} concurrent sessions")]
    AtCapacity(usize),
}

/// Pool configuration (Tier-A knobs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    /// When to rotate personas.
    pub rotation_policy: RotationPolicy,
    /// Maximum concurrent sessions allowed (`0` means unlimited).
    pub max_concurrent_sessions: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            rotation_policy: RotationPolicy::PerSession,
            max_concurrent_sessions: 0,
        }
    }
}

/// Manages the lifecycle of multiple concurrent persona sessions.
#[derive(Debug, Clone)]
pub struct PersonaPool {
    config: PoolConfig,
    rotation_state: RotationState,
    sessions: HashMap<PersonaId, PersonaSession>,
    domain_bindings: HashMap<String, PersonaId>,
    burned_seeds: HashSet<RngSeed>,
    next_id: u64,
    next_seed: u64,
}

impl PersonaPool {
    /// Create a pool with the default configuration.
    #[must_use]
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            rotation_state: RotationState::default(),
            sessions: HashMap::new(),
            domain_bindings: HashMap::new(),
            burned_seeds: HashSet::new(),
            next_id: 1,
            next_seed: 1,
        }
    }

    /// Number of active sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the pool has no active sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    fn any_active_non_burned_session(&self) -> Option<PersonaId> {
        self.sessions
            .values()
            .find(|s| !s.is_burned())
            .map(|s| s.id())
    }

    /// Borrow an active session.
    ///
    /// # Errors
    ///
    /// Returns `PoolError::SessionNotFound` if the id is unknown.
    pub fn session(&self, id: PersonaId) -> Result<&PersonaSession, PoolError> {
        self.sessions.get(&id).ok_or(PoolError::SessionNotFound(id))
    }

    /// Acquire a session for `target_domain`, creating or reusing as needed.
    ///
    /// This is the main lifecycle entry point. It:
    ///   1. checks the sticky domain binding;
    ///   2. decides whether the rotation policy requires a new persona;
    ///   3. selects/assembles/binds a new session if needed;
    ///   4. increments the in-flight counter so rotation cannot race it.
    ///
    /// Call [`Self::release`] when the request/action finishes.
    pub fn acquire(&mut self, target_domain: &str) -> Result<PersonaId, PoolError> {
        if self.config.max_concurrent_sessions > 0
            && self.sessions.len() >= self.config.max_concurrent_sessions
            && !self.domain_bindings.contains_key(target_domain)
        {
            return Err(PoolError::AtCapacity(self.config.max_concurrent_sessions));
        }

        let should_rotate = self
            .config
            .rotation_policy
            .should_rotate(&self.rotation_state, target_domain);

        let reuse_id = if should_rotate {
            None
        } else if self.config.rotation_policy == RotationPolicy::Never {
            // Never rotate: every target shares the first active session.
            self.any_active_non_burned_session()
        } else {
            self.domain_bindings
                .get(target_domain)
                .copied()
                .filter(|id| {
                    self.sessions
                        .get(id)
                        .map(|s| !s.is_burned())
                        .unwrap_or(false)
                })
        };

        let id = match reuse_id {
            Some(id) => id,
            None => {
                let id = self.create_session(target_domain)?;
                self.domain_bindings.insert(target_domain.to_string(), id);
                id
            }
        };

        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(PoolError::SessionNotFound(id))?;
        session.in_flight += 1;
        session.request_count += 1;

        self.config
            .rotation_policy
            .record_request(&mut self.rotation_state, target_domain);

        Ok(id)
    }

    /// Release a previously acquired session.
    ///
    /// # Errors
    ///
    /// Returns `PoolError::SessionNotFound` if the id is unknown.
    pub fn release(&mut self, id: PersonaId) -> Result<(), PoolError> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(PoolError::SessionNotFound(id))?;
        session.in_flight = session.in_flight.saturating_sub(1);
        Ok(())
    }

    /// Rotate the session to a new identity if it has no in-flight requests.
    ///
    /// # Errors
    ///
    /// Returns `PoolError::RotationInProgress` if requests are still active, or
    /// `PoolError::SessionNotFound` if the id is unknown.
    pub fn rotate(&mut self, id: PersonaId, target_domain: &str) -> Result<(), PoolError> {
        let session = self
            .sessions
            .get(&id)
            .ok_or(PoolError::SessionNotFound(id))?;
        if session.in_flight > 0 {
            return Err(PoolError::RotationInProgress(id, session.in_flight));
        }

        // Build a fresh identity with a new seed, keeping the same session id so
        // domain bindings remain valid.
        let seed = self.fresh_seed();
        let new_session = Self::build_session(id, seed)?;
        self.sessions.insert(id, new_session);
        self.domain_bindings.insert(target_domain.to_string(), id);
        self.rotation_state.request_count = 0;
        Ok(())
    }

    /// Mark a session as burned so it will not be reused.
    ///
    /// Domain bindings pointing to this session are removed and its seed is
    /// quarantined.
    ///
    /// # Errors
    ///
    /// Returns `PoolError::SessionNotFound` if the id is unknown.
    pub fn mark_burned(&mut self, id: PersonaId) -> Result<(), PoolError> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(PoolError::SessionNotFound(id))?;
        session.burned = true;
        self.burned_seeds.insert(session.seed);
        self.domain_bindings.retain(|_, bound| *bound != id);
        Ok(())
    }

    /// Serialize a session so it can be persisted and restored later.
    ///
    /// # Errors
    ///
    /// Returns `PoolError::SessionNotFound` if the id is unknown.
    pub fn snapshot(&self, id: PersonaId) -> Result<PersonaSnapshot, PoolError> {
        let session = self.session(id)?;
        Ok(PersonaSnapshot {
            id: id.as_u64(),
            seed: session.seed,
            request_count: session.request_count,
        })
    }

    /// Restore a previously snapshotted session.
    ///
    /// If the recorded id is already in use, a new id is assigned.
    pub fn restore_snapshot(&mut self, snap: PersonaSnapshot) -> Result<PersonaId, PoolError> {
        if self.burned_seeds.contains(&snap.seed) {
            // A burned persona stays burned across restarts.
            return Err(PoolError::Burned(PersonaId(snap.id)));
        }

        let id = if self.sessions.contains_key(&PersonaId(snap.id)) {
            PersonaId(self.fresh_id())
        } else {
            PersonaId(snap.id)
        };
        // Keep `next_id` ahead of every id now in the map. Without this, a
        // restored id above the counter (a snapshot from a pool that had
        // handed out more ids than this one) would be handed out again by a
        // later `create_session`, silently overwriting this session.
        self.next_id = self.next_id.max(id.0.saturating_add(1));

        let mut session = Self::build_session(id, snap.seed)?;
        session.request_count = snap.request_count;
        self.sessions.insert(id, session);
        Ok(id)
    }

    fn create_session(&mut self, target_domain: &str) -> Result<PersonaId, PoolError> {
        let id = PersonaId(self.fresh_id());
        // Avoid handing the same identity to two concurrent sessions when the
        // template pool allows it. Fall back to the last generated session if
        // the pool of distinct personas is exhausted.
        let mut session = Self::build_session(id, self.fresh_seed())?;
        for _ in 0..64 {
            if !self.has_active_identity(&session.identity) {
                break;
            }
            session = Self::build_session(id, self.fresh_seed())?;
        }
        self.sessions.insert(id, session);
        self.rotation_state.previous_target = Some(target_domain.to_string());
        Ok(id)
    }

    fn has_active_identity(&self, identity: &NavigatorProfile) -> bool {
        self.sessions.values().any(|s| {
            s.identity.stealth_profile_name == identity.stealth_profile_name
                && s.identity.hardware_index == identity.hardware_index
                && s.identity.timezone == identity.timezone
        })
    }

    fn build_session(id: PersonaId, seed: RngSeed) -> Result<PersonaSession, PoolError> {
        let identity = crate::fingerprint::identity::seeded_weighted(&seed);
        let overrides = identity.to_overrides();
        #[cfg(feature = "http")]
        let bundle = identity.to_bundle();

        Ok(PersonaSession {
            id,
            seed,
            identity,
            overrides,
            #[cfg(feature = "http")]
            bundle,
            request_count: 0,
            in_flight: 0,
            burned: false,
            #[cfg(feature = "pacing")]
            request_pacer: RequestPacer::default(),
            #[cfg(feature = "human")]
            session_pacing: SessionPacing::new(),
        })
    }

    fn fresh_id(&mut self) -> u64 {
        // Skip ids already in the map (a restored snapshot can sit above the
        // counter) and wrap instead of overflowing when the counter reaches
        // `u64::MAX`: an add-with-overflow panic would kill the process on a
        // path an operator can reach through snapshot restore.
        let mut id = self.next_id;
        while self.sessions.contains_key(&PersonaId(id)) {
            id = id.wrapping_add(1);
        }
        self.next_id = id.wrapping_add(1);
        id
    }

    fn fresh_seed(&mut self) -> RngSeed {
        let seed = RngSeed::from_u64(self.next_seed);
        self.next_seed += 1;
        seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> PersonaPool {
        PersonaPool::new(PoolConfig::default())
    }

    #[test]
    fn lifecycle_acquires_coherent_session() {
        let mut pool = pool();
        let id = pool.acquire("example.com").unwrap();
        let session = pool.session(id).unwrap();
        assert!(!session.identity().user_agent.is_empty());
        assert!(!session.identity().platform.is_empty());
        assert_eq!(session.in_flight(), 1);
        assert_eq!(session.request_count(), 1);

        #[cfg(feature = "http")]
        {
            let bundle = session.bundle();
            assert_eq!(
                crate::rotation::profile_name(bundle.browser),
                session.identity().stealth_profile_name.as_str()
            );
        }
    }

    #[test]
    fn release_decrements_in_flight() {
        let mut pool = pool();
        let id = pool.acquire("example.com").unwrap();
        pool.release(id).unwrap();
        assert_eq!(pool.session(id).unwrap().in_flight(), 0);
    }

    #[test]
    fn rotation_blocked_while_in_flight() {
        let mut pool = pool();
        let id = pool.acquire("example.com").unwrap();
        let err = pool.rotate(id, "example.com").unwrap_err();
        assert!(matches!(err, PoolError::RotationInProgress(_, 1)));
        pool.release(id).unwrap();
        pool.rotate(id, "example.com").unwrap();
    }

    #[test]
    fn sticky_domain_reuses_session() {
        let mut pool = pool();
        let a = pool.acquire("example.com").unwrap();
        pool.release(a).unwrap();
        let b = pool.acquire("example.com").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_domains_get_distinct_sessions() {
        let mut pool = pool();
        let a = pool.acquire("a.com").unwrap();
        pool.release(a).unwrap();
        let b = pool.acquire("b.com").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn burned_session_is_not_reused() {
        let mut pool = pool();
        let id = pool.acquire("example.com").unwrap();
        pool.release(id).unwrap();
        pool.mark_burned(id).unwrap();

        let next = pool.acquire("example.com").unwrap();
        assert_ne!(id, next);
        assert!(pool.session(id).unwrap().is_burned());
    }

    #[test]
    fn burned_seed_stays_quarantined_after_restore() {
        let mut pool = pool();
        let id = pool.acquire("example.com").unwrap();
        let snap = pool.snapshot(id).unwrap();
        pool.mark_burned(id).unwrap();

        let err = pool.restore_snapshot(snap).unwrap_err();
        assert!(matches!(err, PoolError::Burned(_)));
    }

    #[test]
    fn concurrent_sessions_have_distinct_identities() {
        let mut pool = pool();
        let mut ids = Vec::new();
        // The built-in template pool has a finite number of distinct identities,
        // so we acquire exactly that many sessions and assert no collision.
        let n = crate::fingerprint::identity::profile_count();
        for i in 0..n {
            let id = pool.acquire(&format!("site{i}.com")).unwrap();
            ids.push(id);
        }
        let mut seen = std::collections::HashSet::new();
        for id in &ids {
            let identity = pool.session(*id).unwrap().identity();
            let key = (
                identity.stealth_profile_name.clone(),
                identity.hardware_index,
                identity.timezone.clone(),
            );
            assert!(
                seen.insert(key),
                "duplicate identity for concurrent session"
            );
        }
    }

    #[test]
    fn snapshot_round_trip_preserves_identity() {
        let mut pool = pool();
        let id = pool.acquire("example.com").unwrap();
        let ua_before = pool.session(id).unwrap().identity().user_agent.clone();
        let snap = pool.snapshot(id).unwrap();
        pool.release(id).unwrap();

        let restored = pool.restore_snapshot(snap).unwrap();
        let ua_after = pool
            .session(restored)
            .unwrap()
            .identity()
            .user_agent
            .clone();
        assert_eq!(ua_before, ua_after);
    }

    #[test]
    fn request_count_is_preserved_by_snapshot() {
        let mut pool = pool();
        let id = pool.acquire("example.com").unwrap();
        pool.release(id).unwrap();
        let id = pool.acquire("example.com").unwrap();
        pool.release(id).unwrap();

        let snap = pool.snapshot(id).unwrap();
        assert_eq!(snap.request_count, 2);
        let restored = pool.restore_snapshot(snap).unwrap();
        assert_eq!(pool.session(restored).unwrap().request_count(), 2);
    }

    #[test]
    fn rotation_policy_per_target_rotates_on_domain_change() {
        let mut pool = PersonaPool::new(PoolConfig {
            rotation_policy: RotationPolicy::PerTarget,
            max_concurrent_sessions: 0,
        });
        let a = pool.acquire("a.com").unwrap();
        pool.release(a).unwrap();
        let b = pool.acquire("b.com").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rotation_policy_never_never_rotates() {
        let mut pool = PersonaPool::new(PoolConfig {
            rotation_policy: RotationPolicy::Never,
            max_concurrent_sessions: 0,
        });
        let a = pool.acquire("a.com").unwrap();
        pool.release(a).unwrap();
        let b = pool.acquire("b.com").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn capacity_limit_blocks_new_sessions() {
        let mut pool = PersonaPool::new(PoolConfig {
            rotation_policy: RotationPolicy::PerSession,
            max_concurrent_sessions: 2,
        });
        let a = pool.acquire("a.com").unwrap();
        let b = pool.acquire("b.com").unwrap();
        assert!(pool.acquire("c.com").is_err());
        pool.release(a).unwrap();
        pool.release(b).unwrap();
        // Reusing an existing domain binding is allowed even at capacity.
        assert_eq!(pool.acquire("a.com").unwrap(), a);
    }

    #[test]
    fn same_seed_reproduces_identical_persona() {
        // G314: a seed reproduces the exact identity for incident triage.
        let mut pool_a = PersonaPool::new(PoolConfig::default());
        let mut pool_b = PersonaPool::new(PoolConfig::default());

        let id_a = pool_a.acquire("example.com").unwrap();
        let snap_a = pool_a.snapshot(id_a).unwrap();

        let id_b = pool_b.restore_snapshot(snap_a).unwrap();
        let identity_a = pool_a.session(id_a).unwrap().identity().clone();
        let identity_b = pool_b.session(id_b).unwrap().identity().clone();
        assert_eq!(identity_a, identity_b);
    }

    /// Regression: `restore_snapshot` inserted the restored id without
    /// advancing `next_id`. A snapshot carrying an id above the counter (one
    /// taken from a pool that had handed out more ids) was later handed out
    /// again by `create_session`, whose `sessions.insert` silently OVERWROTE
    /// the restored session. The restored persona vanished mid-flight and any
    /// domain binding to it pointed at an identity the operator never
    /// approved. Restore must move the counter past every live id.
    #[test]
    fn restored_id_is_never_reissued_by_later_sessions() {
        let mut donor = pool();
        // Hand out several ids in the donor so the snapshot id is well above
        // a fresh pool's counter.
        let mut last = donor.acquire("d0.com").unwrap();
        for i in 1..6 {
            last = donor.acquire(&format!("d{i}.com")).unwrap();
        }
        let snap = donor.snapshot(last).unwrap();
        assert!(snap.id > 1);

        let mut pool = pool();
        let restored = pool.restore_snapshot(snap).unwrap();
        let restored_ua = pool.session(restored).unwrap().identity().user_agent.clone();

        // Every session created after the restore must get a FRESH id and
        // must not disturb the restored session.
        for i in 0..8 {
            let id = pool.acquire(&format!("fresh{i}.com")).unwrap();
            assert_ne!(id, restored, "create_session reissued the restored id");
        }
        assert_eq!(
            pool.session(restored).unwrap().identity().user_agent,
            restored_ua,
            "the restored session was overwritten by a later create_session"
        );
    }

    /// Boundary twin of the id-collision regression: a snapshot whose id is
    /// `u64::MAX` must restore without overflowing the counter bump.
    #[test]
    fn restore_handles_max_id_without_overflow() {
        let mut pool = pool();
        let seed = crate::sampling::RngSeed::from_u64(77);
        let restored = pool
            .restore_snapshot(PersonaSnapshot {
                id: u64::MAX,
                seed,
                request_count: 0,
            })
            .unwrap();
        assert_eq!(restored.as_u64(), u64::MAX);
        // A subsequent acquisition still works and gets a different id.
        let id = pool.acquire("example.com").unwrap();
        assert_ne!(id, restored);
    }
}
