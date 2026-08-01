//! Wire-fingerprint **cluster membership**: the anti-uniqueness self-check
//! (G048–G051).
//!
//! A spoofed TLS/HTTP-2 fingerprint that is *byte-perfect Firefox* still loses
//! if it is the **only** client on the internet emitting that exact shape: a
//! unique fingerprint is itself a stable identifier (it tracks you across
//! sessions even with cookies cleared). The defense is not "look like a
//! browser" but "look like a **populated** browser cluster", collide with the
//! JA4/Akamai that millions of real users share.
//!
//! This module measures exactly that, and **only** that. Given a fingerprint
//! the operator's own stack emits (recovered from a probe such as
//! `tls.peet.ws/api/all`), it reports which known real-browser
//! [`FingerprintTarget`](crate::fingerprint::tls_targets::FingerprintTarget)s
//! that shape collides with. It is a screwdriver: it transforms *the operator's
//! own emitted fingerprint* into a membership verdict. It never inspects a
//! remote target, never claims a vulnerability, and never scores anyone.
//!
//! ## Soundness, what [`ClusterVerdict::Distinguishable`] does and does not mean
//!
//! A `Distinguishable` verdict means "this shape matched **no entry in the
//! bundled catalogue** on the primary axis." That is a fact about *catalogue
//! coverage*, **not** proof the fingerprint is globally unique, the catalogue
//! is a finite snapshot of published targets, and the real cluster a shape
//! belongs to may simply not be bundled yet. So `Distinguishable` lowers the
//! operator's confidence that they blend in; it never raises a claim that the
//! fingerprint is trackable in the wild. Closing the gap is "add the measured
//! target," never "assert uniqueness."
//!
//! ## Why JA4 is the primary axis, Akamai-H2 the corroborator
//!
//! - **JA4** sorts the GREASE-stripped cipher and extension lists before
//!   hashing (FoxIO spec; see [`compute_ja4`](crate::fingerprint::ja3::compute_ja4)),
//!   so it is *stable across handshakes*, unlike a raw ClientHello capture
//!   whose GREASE values and positions vary every connection. A stable surface
//!   is the only kind a cluster can be defined over, so JA4 is the **required**
//!   axis: membership is asserted only when JA4 matches.
//! - **Akamai HTTP/2** (`SETTINGS|WINDOW_UPDATE|PRIORITY|header-order`) is set
//!   by the engine's networking stack, not JavaScript. It *corroborates*: a JA4
//!   that matches Firefox while the H2 frame says something else is an
//!   incoherent shape, so a **probed** Akamai that contradicts the JA4 match
//!   breaks membership rather than being silently ignored. When it contradicts,
//!   parse both sides with
//!   [`akamai_h2::AkamaiH2Fingerprint`](crate::fingerprint::akamai_h2) and
//!   [`diff`](crate::fingerprint::akamai_h2::AkamaiH2Fingerprint::diff) them to
//!   localize the divergence to the exact frame field (which SETTINGS value,
//!   pseudo-header order, …) (the surface here is a coarse Matched/Mismatched).
//! - **JA3** is order-sensitive and deprecated; **peetprint** is a `peet.ws`
//!   composite. Both are recorded and, when probed, may contradict, but neither
//!   alone establishes membership.
//!
//! Every surface is tri-state ([`SurfaceMatch`]): `Matched`, `Mismatched`, or
//! `NotProbed`. Collapsing "not probed" into "mismatched" would silently turn an
//! un-probed surface into a false contradiction, so the distinction is kept
//! explicit end to end.

use crate::fingerprint::tls_targets::{FingerprintTarget, FINGERPRINT_TARGETS};

/// One surface's comparison outcome. Kept tri-state so "the probe never
/// recovered this surface" is never confused with "this surface disagreed."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceMatch {
    /// The observation carried this surface and it equals the target's.
    Matched,
    /// The observation carried this surface and it differs from the target's.
    Mismatched,
    /// The observation did not carry this surface; nothing can be said.
    NotProbed,
}

impl SurfaceMatch {
    fn of(observed: Option<&str>, target: &str) -> Self {
        match observed {
            None => Self::NotProbed,
            Some(value) if value == target => Self::Matched,
            Some(_) => Self::Mismatched,
        }
    }

    /// True only for [`SurfaceMatch::Matched`].
    #[must_use]
    pub fn is_matched(self) -> bool {
        matches!(self, Self::Matched)
    }

    /// True only for [`SurfaceMatch::Mismatched`] (a probed disagreement, not an
    /// absence).
    #[must_use]
    pub fn is_mismatched(self) -> bool {
        matches!(self, Self::Mismatched)
    }
}

/// A fingerprint the operator's own transport emits, as recovered from a wire
/// probe. Every field is optional because a given probe recovers only the
/// surfaces it can see (`tls.peet.ws/api/all` yields all four; a passive TLS
/// sniffer may yield only the JA3 string).
///
/// `ja3` is compared as the full canonical JA3 **string**
/// (`771,ciphers,exts,groups,formats`) to match the catalogue's representation,
/// not the MD5 hash.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservedFingerprint {
    /// Full canonical JA3 string, GREASE-stripped (not the MD5 hash).
    pub ja3: Option<String>,
    /// JA4 string, e.g. `t13d1717h2_5b57614c22b0_e6dcd7ae0a9e`.
    pub ja4: Option<String>,
    /// Akamai HTTP/2 fingerprint, `settings|window_update|priority|header-order`.
    pub akamai_h2: Option<String>,
    /// peetprint HTTP/2 composite hash.
    pub peet_h2: Option<String>,
}

impl ObservedFingerprint {
    /// Build an observation carrying only a JA4 string, the most common case,
    /// since JA4 is the stable primary axis.
    #[must_use]
    pub fn from_ja4(ja4: impl Into<String>) -> Self {
        Self {
            ja4: Some(ja4.into()),
            ..Self::default()
        }
    }

    /// True when the primary axis (JA4) was recovered. A verdict computed
    /// without it is weak, membership cannot be asserted on a corroborating
    /// surface alone.
    #[must_use]
    pub fn has_primary_axis(&self) -> bool {
        self.ja4.is_some()
    }
}

/// How one observed fingerprint lines up against one catalogue target, surface
/// by surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMatch {
    /// The catalogue label this observation was compared against.
    pub label: &'static str,
    /// JA3 string comparison.
    pub ja3: SurfaceMatch,
    /// JA4 comparison (the primary axis).
    pub ja4: SurfaceMatch,
    /// Akamai-H2 comparison (the corroborating axis).
    pub akamai: SurfaceMatch,
    /// peetprint comparison.
    pub peet: SurfaceMatch,
}

impl ClusterMatch {
    /// Count of surfaces that were probed and matched (0–4).
    #[must_use]
    pub fn matched_surfaces(&self) -> u8 {
        u8::from(self.ja3.is_matched())
            + u8::from(self.ja4.is_matched())
            + u8::from(self.akamai.is_matched())
            + u8::from(self.peet.is_matched())
    }

    /// True when any **probed** surface disagrees with this target. A `NotProbed`
    /// surface never contributes (absence is not contradiction).
    #[must_use]
    pub fn contradicts(&self) -> bool {
        self.ja3.is_mismatched()
            || self.ja4.is_mismatched()
            || self.akamai.is_mismatched()
            || self.peet.is_mismatched()
    }

    /// True when the observation is a member of this target's cluster: the
    /// primary axis (JA4) matched **and** no other probed surface contradicts
    /// it. JA4 matching makes `contradicts()` consider only the corroborating
    /// surfaces, so a probed-but-disagreeing Akamai/JA3/peet still breaks it.
    #[must_use]
    pub fn is_member(&self) -> bool {
        self.ja4.is_matched() && !self.contradicts()
    }

    /// True when at least one surface matched, used to rank the nearest target
    /// when no member exists.
    #[must_use]
    pub fn any_match(&self) -> bool {
        self.matched_surfaces() > 0
    }
}

/// The membership verdict for one observed fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterVerdict {
    /// The observation matched ≥1 catalogue target on the primary axis (JA4)
    /// with no contradicting corroboration: it blends into that real-browser
    /// crowd. Carries every such member.
    InCluster {
        /// Targets the observation is a member of.
        matches: Vec<ClusterMatch>,
    },
    /// No catalogue target was a member match. The observation is
    /// distinguishable **from the bundled catalogue**: see the module-level
    /// soundness note: this is a coverage fact, not a uniqueness proof.
    Distinguishable {
        /// The closest target by matched-surface count, when any surface matched.
        nearest: Option<ClusterMatch>,
        /// True when the primary axis (JA4) was never probed, so the verdict
        /// rests only on corroborating surfaces and a JA4 re-probe is warranted
        /// before trusting it.
        weak_evidence_only: bool,
    },
}

impl ClusterVerdict {
    /// True when the observation blends into a known real-browser cluster.
    #[must_use]
    pub fn is_in_cluster(&self) -> bool {
        matches!(self, ClusterVerdict::InCluster { .. })
    }

    /// The labels of every real-browser target the observation is a member of
    /// (empty unless [`Self::is_in_cluster`]).
    #[must_use]
    pub fn cluster_labels(&self) -> Vec<&'static str> {
        match self {
            ClusterVerdict::InCluster { matches } => matches.iter().map(|m| m.label).collect(),
            ClusterVerdict::Distinguishable { .. } => Vec::new(),
        }
    }
}

/// Compare one observation against one target, surface by surface.
#[must_use]
fn match_against(observed: &ObservedFingerprint, target: &FingerprintTarget) -> ClusterMatch {
    ClusterMatch {
        label: target.label,
        ja3: SurfaceMatch::of(observed.ja3.as_deref(), target.ja3),
        ja4: SurfaceMatch::of(observed.ja4.as_deref(), target.ja4),
        akamai: SurfaceMatch::of(observed.akamai_h2.as_deref(), target.akamai_h2),
        peet: SurfaceMatch::of(observed.peet_h2.as_deref(), target.peet_h2),
    }
}

/// Classify an observed fingerprint against the bundled real-browser catalogue.
///
/// Returns [`ClusterVerdict::InCluster`] when the observation is a member of ≥1
/// target (primary axis JA4 matched, nothing probed contradicts), otherwise
/// [`ClusterVerdict::Distinguishable`] with the nearest partial match. See the
/// module soundness note on what `Distinguishable` does and does not assert.
///
/// # Examples
///
/// ```
/// use guise::fingerprint::cluster::{classify_observed, ObservedFingerprint};
/// use guise::fingerprint::tls_targets::lookup;
///
/// // A shape that reproduces a bundled target's JA4 (and a matching Akamai) is
/// // in-cluster.
/// let ff = lookup("firefox-150-linux").unwrap();
/// let observed = ObservedFingerprint {
///     ja4: Some(ff.ja4.to_string()),
///     akamai_h2: Some(ff.akamai_h2.to_string()),
///     ..Default::default()
/// };
/// let verdict = classify_observed(&observed);
/// assert!(verdict.is_in_cluster());
/// assert!(verdict.cluster_labels().contains(&"firefox-150-linux"));
///
/// // A JA4 that exists in no bundled target is distinguishable from the catalogue.
/// let alien = ObservedFingerprint::from_ja4("t13d9999h2_deadbeefcafe_0123456789ab");
/// assert!(!classify_observed(&alien).is_in_cluster());
/// ```
#[must_use]
pub fn classify_observed(observed: &ObservedFingerprint) -> ClusterVerdict {
    classify_against(observed, FINGERPRINT_TARGETS)
}

/// [`classify_observed`] against an explicit target set, the testable core, so
/// the catalogue can be substituted in unit tests, or extended with Tier-B
/// targets via [`tls_targets::builtin_with`](crate::fingerprint::tls_targets::builtin_with).
/// The slice need not be `'static` (only each target's string fields are); this
/// lets a caller classify against a runtime-built `Vec<FingerprintTarget>`.
#[must_use]
pub fn classify_against(
    observed: &ObservedFingerprint,
    targets: &[FingerprintTarget],
) -> ClusterVerdict {
    let all: Vec<ClusterMatch> = targets
        .iter()
        .map(|target| match_against(observed, target))
        .collect();

    let members: Vec<ClusterMatch> = all.iter().filter(|m| m.is_member()).cloned().collect();
    if !members.is_empty() {
        return ClusterVerdict::InCluster { matches: members };
    }

    // No member, pick the nearest among targets that matched *something*. Rank
    // a primary-axis (JA4) match ABOVE an equal count of corroborator-only
    // matches: when JA4 matched but a corroborator contradicts, "you emit this
    // target's JA4 but your H2/JA3 disagrees" is the actionable near-miss, more
    // informative than an unrelated target that merely shares one Akamai value.
    let nearest = all
        .into_iter()
        .filter(ClusterMatch::any_match)
        .max_by_key(|m| (m.ja4.is_matched(), m.matched_surfaces()));

    ClusterVerdict::Distinguishable {
        nearest,
        weak_evidence_only: !observed.has_primary_axis(),
    }
}

#[cfg(test)]
#[path = "cluster/tests.rs"]
mod tests;
