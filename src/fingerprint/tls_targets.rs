//! TLS and HTTP/2 fingerprint targets for browser-shaped transports.
//!
//! WAFs can classify the TLS ClientHello and HTTP/2 SETTINGS frame before
//! any JavaScript runs. This catalogue records the target strings that Santh
//! clients use when selecting or validating a browser-shaped transport.
//!
//! Role (G010): the **versioned per-label target** catalogue, each entry
//! (`chrome-146-linux`, `firefox-150-linux`, `firefox-151-linux`, …) carries the
//! full JA3 + JA4 + Akamai-H2 + peet strings for one published browser/version/OS
//! target. These are VERSIONED snapshots, do not assume they match the current
//! persona. Sibling catalogues: `tls_profiles` (the structured source) and
//! `chrome_tls` (Chrome diagnostic snapshots).
//!
//! All built-in targets are required to be JA3/JA4 count-consistent; the
//! `ja4_counts_match_ja3` check is enforced over the whole catalogue by tests.
//!
//! Submodules (Law-5 responsibility split): [`validate`] owns the field-shape
//! checks shared by the built-in audit and the Tier-B loader; `tier_b` owns the
//! drop-in TOML catalogue loader (`tier-b-toml` feature).

use serde::{Deserialize, Serialize};

mod validate;
pub use validate::{ja4_counts_match_ja3, validate_target_fields};

#[cfg(feature = "tier-b-toml")]
mod tier_b;
#[cfg(feature = "tier-b-toml")]
pub use tier_b::{load_targets_from_toml, TargetLoadError};

#[cfg(test)]
#[path = "tls_targets/tests.rs"]
mod tests;
#[cfg(all(test, feature = "tier-b-toml"))]
#[path = "tls_targets/tier_b_tests.rs"]
mod tier_b_tests;

/// One vendor-shaped TLS and HTTP/2 fingerprint target.
///
/// The four fingerprint fields are published string formats. Consumers match
/// on whichever representation their probe or upstream WAF reports.
///
/// `Copy` because every field is `&'static str`: built-in entries borrow
/// program-static literals, and Tier-B entries loaded from disk leak their
/// strings to `'static` (a load-once catalogue), so both are uniformly cheap to
/// pass by value and concatenate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintTarget {
    /// Stable lowercase label for the target profile.
    pub label: &'static str,
    /// JA3 fingerprint string: TLS version, ciphers, extensions, groups, and
    /// EC point formats.
    pub ja3: &'static str,
    /// JA4 fingerprint string.
    pub ja4: &'static str,
    /// Akamai HTTP/2 fingerprint string in
    /// `settings|window_update|priority|headers` form.
    pub akamai_h2: &'static str,
    /// Peet HTTP/2 fingerprint hash.
    pub peet_h2: &'static str,
}

/// Bundled browser TLS and HTTP/2 fingerprint targets.
///
/// Adding a target is compatible. Removing or changing a label is a breaking
/// contract change for callers that persist profile names.
pub const FINGERPRINT_TARGETS: &[FingerprintTarget] = &[
    // The CURRENT shipping reynard persona. Measured live 2026-06-12 against
    // `tls.peet.ws/api/all` from a reynard (Camoufox-150) page, AFTER the
    // camoufox.cfg cipher fix that restored `ecdhe_ecdsa_aes_128_sha` (0xc009):
    // 17 ciphers (`t13d1717h2`). The degreased cipher/extension/H2 sets were
    // confirmed == stock Firefox 150 in the cipher-fix verification run.
    FingerprintTarget {
        label: "firefox-150-linux",
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0",
        ja4: "t13d1717h2_5b57614c22b0_e6dcd7ae0a9e",
        akamai_h2: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
        peet_h2: "6ea73faa8fc5aac76bded7bd238f6433",
    },
    // Current-stable Firefox. Measured live 2026-06-12 by driving the host's stock
    // `Firefox/151.0` to `tls.peet.ws/api/all`. JA3/JA4 are count-consistent (16
    // ciphers / 17 extensions → `t13d1617h2`). It is the FF-150 shape with cipher
    // `0xc009` dropped (17→16); the extension/group shape, and therefore the JA4
    // `_c` hash `e6dcd7ae0a9e`: is unchanged from FF-150, so only the cipher count
    // and JA4 `_b` cipher-hash move. The H2 SETTINGS are identical to FF-150
    // (Firefox's frame layer is version-stable here).
    FingerprintTarget {
        label: "firefox-151-linux",
        ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0",
        ja4: "t13d1617h2_86a278354501_e6dcd7ae0a9e",
        akamai_h2: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
        peet_h2: "6ea73faa8fc5aac76bded7bd238f6433",
    },
    // Current-stable Chrome. Measured live 2026-06-12 by driving the host's stock
    // `Chrome/146` to `tls.peet.ws/api/all`. The JA4 `t13d1517h2_8daaf6152771_
    // b6f405a00624` is the authoritative, cross-connection-STABLE fingerprint (JA4
    // sorts extensions). The `ja3` string is a single representative SAMPLE:
    // Chrome shuffles its TLS extension order per connection (RFC-8701-style
    // randomization), so the JA3 hash varies run-to-run while the JA4 does not 
    // do not treat this JA3 as a fixed match key. Count-consistent regardless of
    // order (15 ciphers / 17 extensions → `t13d1517h2`).
    FingerprintTarget {
        label: "chrome-146-linux",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-45-18-27-10-35-16-43-65281-65037-11-23-51-13-17613-41,4588-29-23-24,0",
        ja4: "t13d1517h2_8daaf6152771_b6f405a00624",
        akamai_h2: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        peet_h2: "52d84b11737d980aef856699f885ca86",
    },
];

/// Look up the canonical fingerprint target for `label`.
///
/// Returns `None` when `label` is not one of the bundled target labels.
///
/// # Example
///
/// ```rust
/// use guise::fingerprint::tls_targets::lookup;
///
/// let target = lookup("chrome-146-linux").expect("chrome-146-linux must ship");
/// assert!(target.ja3.starts_with("771,"));
/// assert!(!target.ja4.is_empty());
/// ```
#[must_use]
pub fn lookup(label: &str) -> Option<&'static FingerprintTarget> {
    FINGERPRINT_TARGETS.iter().find(|t| t.label == label)
}

/// Return every bundled target label in declaration order.
#[must_use]
pub fn all_labels() -> Vec<&'static str> {
    FINGERPRINT_TARGETS.iter().map(|t| t.label).collect()
}

/// The built-in catalogue followed by `extra` (e.g. Tier-B targets from
/// [`load_targets_from_toml`]). The catalogue to hand
/// [`cluster::classify_against`](crate::fingerprint::cluster::classify_against)
/// when extending anti-uniqueness coverage beyond the shipped targets.
#[must_use]
pub fn builtin_with(extra: &[FingerprintTarget]) -> Vec<FingerprintTarget> {
    FINGERPRINT_TARGETS
        .iter()
        .copied()
        .chain(extra.iter().copied())
        .collect()
}
