//! The X049 Layer-2 wire self-probe: compare what we ACTUALLY emit on the wire
//! (a TTL/Akamai capture a peer or `tls.peet.ws` reports about our egress)
//! against the persona's expected wire identity, per layer. It reports, it
//! never claims exploitability, and an absent measurement is never read as
//! agreement (Law: no silent fallback to a passing verdict).

use super::profiles::pair_for_profile;
use crate::fingerprint::{profile_os_network_stack, StealthProfile, UserAgentPlatform};

/// A Layer-2 wire signature *observed* about our own egress, what a peer, WAF,
/// or a reflector like `tls.peet.ws` reports seeing on the wire (past NAT).
///
/// Every field is optional: a given probe may report only some layers (peet
/// reports both; a raw-socket TTL probe reports only the TTL). A field left
/// `None` is simply not cross-checked (it is never treated as agreement).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireCapture {
    /// Raw IP TTL seen on a received packet from us (before de-hopping).
    pub observed_ttl: Option<u8>,
    /// Observed Akamai HTTP/2 fingerprint string
    /// (`SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header-order`).
    pub akamai_fingerprint: Option<String>,
    /// Observed JA4T (FoxIO TCP-client fingerprint) computed from our egress SYN:
    /// `window_size_option-kinds_MSS_window-scale`. Compared against the persona's
    /// expected JA4T with autotuned-window OS families wildcarding the window
    /// see [`crate::fingerprint::OsNetworkStack::ja4t_matches_observed`].
    pub observed_ja4t: Option<String>,
}

impl WireCapture {
    /// Whether any layer is present to cross-check.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observed_ttl.is_none()
            && self.akamai_fingerprint.is_none()
            && self.observed_ja4t.is_none()
    }
}

/// One Layer-2 wire layer that contradicts the persona's claimed identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireLayerMismatch {
    /// The de-hopped egress TTL implies a different OS family than the persona.
    Ttl {
        /// OS family the persona claims.
        expected_os: UserAgentPlatform,
        /// Initial TTL that OS would emit.
        expected_initial_ttl: u8,
        /// Initial TTL inferred from the observed packet.
        observed_initial_ttl: u8,
    },
    /// The observed Akamai HTTP/2 fingerprint differs from the persona's model
    /// e.g. a Chrome persona driven through a Firefox engine emits Firefox H2.
    Akamai {
        /// Full Akamai string the persona's browser family should emit.
        expected: String,
        /// Full Akamai string actually observed on the wire.
        observed: String,
    },
    /// The observed JA4T (egress SYN TCP fingerprint) contradicts the persona's
    /// claimed OS, the TCP-layer analogue of the Akamai tell, and the exact
    /// "TLS says Windows, TCP says Linux" leak X049 exists to catch before a
    /// detector does. The window field is wildcarded for autotuned-window OS
    /// families, so this fires on an option/MSS/wscale-tail divergence (or a
    /// fixed-window mismatch), not on benign per-connection window variation.
    Ja4t {
        /// JA4T the persona's TCP/IP stack should emit (`*` window for autotuned).
        expected: String,
        /// JA4T actually observed on the egress SYN.
        observed: String,
    },
}

impl WireLayerMismatch {
    /// For an [`Akamai`](Self::Akamai) mismatch, localize the divergence to the
    /// exact HTTP/2 frame fields with the canonical
    /// [`AkamaiH2Fingerprint`](crate::fingerprint::akamai_h2) parser, so a
    /// report can say "pseudo-header order m,p,a,s vs m,a,s,p" or
    /// "INITIAL_WINDOW_SIZE 131072 vs 6291456" instead of two opaque strings the
    /// operator must eyeball-diff. The divergences are computed `observed`-vs-
    /// `expected` (the wire vs the persona).
    ///
    /// Returns `None` for a non-Akamai mismatch, or when either side does not
    /// parse. This is an **additive** localizer: the authoritative `expected` /
    /// `observed` strings stay on the variant and the mismatch is already fully
    /// reported without it, so a `None` here never hides a divergence, it only
    /// means "structural localization unavailable; read the raw strings."
    #[must_use]
    pub fn akamai_field_divergences(
        &self,
    ) -> Option<Vec<crate::fingerprint::akamai_h2::AkamaiH2Divergence>> {
        let Self::Akamai { expected, observed } = self else {
            return None;
        };
        use crate::fingerprint::akamai_h2::AkamaiH2Fingerprint;
        let expected = AkamaiH2Fingerprint::parse(expected).ok()?;
        let observed = AkamaiH2Fingerprint::parse(observed).ok()?;
        Some(observed.diff(&expected))
    }
}

/// Verdict of probing our own egress against a persona's expected wire identity.
///
/// This is the X049 self-probe: *detect "TLS says Windows, TCP says Linux" in
/// our own egress before a detector does.* It does not claim anything is
/// exploitable, it reports, per layer, whether the wire we actually emit
/// betrays the persona we claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireSelfProbe {
    /// Every *measured* layer agrees with the persona's expected wire identity.
    Coherent,
    /// At least one measured layer contradicts the persona; each mismatch is
    /// named so the operator knows exactly which layer will leak.
    Incoherent(Vec<WireLayerMismatch>),
    /// No layer was measurable (an empty capture), explicitly *not* `Coherent`,
    /// so an absent measurement can never read as agreement (Law: no silent
    /// fallback to a passing verdict).
    Unmeasured,
}

impl WireSelfProbe {
    /// Whether the probe found the egress coherent with the persona.
    #[must_use]
    pub const fn is_coherent(&self) -> bool {
        matches!(self, Self::Coherent)
    }
}

/// Probe our own observed egress against a persona's expected Layer-2 wire
/// identity, returning a per-layer verdict.
///
/// Compares whichever layers the capture supplies:
/// - **TTL**: de-hops the observed TTL ([`crate::fingerprint::infer_initial_ttl`])
///   and compares to the persona's TCP/IP stack initial TTL. A `0` (unmeasurable)
///   TTL is skipped, not failed.
/// - **Akamai HTTP/2**: compares the observed fingerprint to the persona's
///   browser-family [`super::profiles::H2Profile::akamai_fingerprint`]. Skipped
///   when the persona has no modeled HTTP/2 profile (e.g. IE11), we cannot
///   assert a mismatch we have no model for.
/// - **JA4T**: compares the observed egress-SYN TCP fingerprint to the persona's
///   [`crate::fingerprint::OsNetworkStack::ja4t`], window-wildcarded for
///   autotuned-window OS families so only an option/MSS/wscale-tail (or
///   fixed-window) divergence flags, the TCP-layer half of the "TLS says X, TCP
///   says Y" self-gate.
///
/// Returns [`WireSelfProbe::Unmeasured`] when no layer could be compared (so an
/// empty or all-skipped capture never masquerades as agreement), `Coherent` when
/// every compared layer agrees, and `Incoherent` listing every disagreement.
#[must_use]
pub fn persona_wire_self_probe(profile: StealthProfile, capture: &WireCapture) -> WireSelfProbe {
    let mut mismatches = Vec::new();
    let mut compared = 0_usize;

    if let Some(observed_ttl) = capture.observed_ttl {
        let observed_initial = crate::fingerprint::infer_initial_ttl(observed_ttl);
        // A de-hopped initial of 0 means the TTL was unmeasurable; don't compare.
        if observed_initial != 0 {
            compared += 1;
            let stack = profile_os_network_stack(profile);
            if stack.initial_ttl != observed_initial {
                mismatches.push(WireLayerMismatch::Ttl {
                    expected_os: stack.os,
                    expected_initial_ttl: stack.initial_ttl,
                    observed_initial_ttl: observed_initial,
                });
            }
        }
    }

    if let Some(observed_akamai) = capture.akamai_fingerprint.as_deref() {
        if let Some((_, h2)) = pair_for_profile(profile) {
            compared += 1;
            let expected = h2.akamai_fingerprint();
            if expected != observed_akamai {
                mismatches.push(WireLayerMismatch::Akamai {
                    expected,
                    observed: observed_akamai.to_string(),
                });
            }
        }
    }

    if let Some(observed_ja4t) = capture.observed_ja4t.as_deref() {
        compared += 1;
        let stack = profile_os_network_stack(profile);
        // Window-aware comparison: autotuned-window OS families wildcard the
        // window field so per-connection variation isn't a false tell; the
        // option/MSS/wscale tail (and a fixed window) must match. Fails closed on
        // a malformed observation (it is never read as agreement).
        if !stack.ja4t_matches_observed(observed_ja4t) {
            // The persona's own rendered JA4T is the expected side of the report;
            // it always renders for a shipped persona, but if a future stack can't
            // render we surface a loud marker rather than hide the divergence.
            let expected = stack
                .ja4t()
                .unwrap_or_else(|_| "<unrenderable-ja4t>".to_string());
            mismatches.push(WireLayerMismatch::Ja4t {
                expected,
                observed: observed_ja4t.to_string(),
            });
        }
    }

    if compared == 0 {
        WireSelfProbe::Unmeasured
    } else if mismatches.is_empty() {
        WireSelfProbe::Coherent
    } else {
        WireSelfProbe::Incoherent(mismatches)
    }
}
