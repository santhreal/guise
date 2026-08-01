//! Per-engine transport wire profiles: canonical request-header insertion order
//! and the HTTP/2 SETTINGS / Akamai fingerprint model, plus the profile→pair
//! lookups. This is the DATA layer the transport-coherence predicates resolve
//! against (no policy lives here, only the per-browser-family wire shapes).

use std::collections::{HashMap, HashSet};

use crate::fingerprint::StealthProfile;
use crate::rotation::named_profile;

/// Canonical request-header insertion order for one browser family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderOrder {
    /// Family name: `"chrome"`, `"firefox"`, or `"safari"`.
    pub family: &'static str,
    /// Header names in the order a browser writes them on navigation requests.
    pub slots: &'static [&'static str],
}

/// Chromium and Edge canonical navigation request-header order.
pub const CHROME_HEADER_ORDER: HeaderOrder = HeaderOrder {
    family: "chrome",
    slots: &[
        "host",
        "connection",
        "cache-control",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
        "cookie",
    ],
};

/// Firefox canonical navigation request-header order.
pub const FIREFOX_HEADER_ORDER: HeaderOrder = HeaderOrder {
    family: "firefox",
    slots: &[
        "host",
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "connection",
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "cookie",
    ],
};

/// Safari canonical navigation request-header order.
pub const SAFARI_HEADER_ORDER: HeaderOrder = HeaderOrder {
    family: "safari",
    slots: &[
        "host",
        "accept",
        "accept-encoding",
        "connection",
        "user-agent",
        "accept-language",
        "cookie",
    ],
};

/// HTTP/2 SETTINGS frame values, order, the initial connection window update,
/// the PRIORITY-frame field, and the pseudo-header emit order, the four
/// segments of the Akamai HTTP/2 fingerprint, modeled structurally.
///
/// The Akamai fingerprint a WAF reports is `SETTINGS|WINDOW_UPDATE|PRIORITY|
/// pseudo-header-order` (e.g. Firefox `1:65536;2:0;4:131072;5:16384|12517377|0|
/// m,p,a,s`). Earlier this struct modeled only the first two segments, so the
/// L2 coherence gate was blind to the PRIORITY frame and the pseudo-header order
///: two real per-engine discriminators. All four are now first-class; render
/// the canonical wire string with [`H2Profile::akamai_fingerprint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2Profile {
    /// Family name; same vocabulary as [`HeaderOrder::family`].
    pub family: &'static str,
    /// `(setting_id, value)` in browser emit order.
    pub settings: &'static [(u16, u32)],
    /// Initial connection window-size increment sent after SETTINGS.
    pub initial_window_increment: u32,
    /// The PRIORITY-frame segment (Akamai third field). Modern browsers that
    /// drive stream prioritization via SETTINGS / RFC 9218 send no standalone
    /// PRIORITY frames on connection open and render as `"0"`. An engine that
    /// does send them renders the faithful `streamId:exclusive:dependsOn:weight`
    /// wire form (e.g. older Firefox `3:0:0:201`), so this is kept as the exact
    /// wire string rather than a parsed shape we might render back differently.
    pub priority: &'static str,
    /// Pseudo-header emit order (Akamai fourth field): `m` = `:method`,
    /// `a` = `:authority`, `s` = `:scheme`, `p` = `:path`. A load-bearing
    /// per-engine discriminator that is stable across versions: Chrome emits
    /// `m,a,s,p`, Firefox `m,p,a,s`, Safari `m,s,p,a`. A persona whose transport
    /// emits the wrong order for its claimed engine is fingerprintable here even
    /// when SETTINGS match.
    pub pseudo_header_order: &'static str,
}

impl H2Profile {
    /// Render the full Akamai HTTP/2 fingerprint string from the model:
    /// `SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header-order`.
    ///
    /// This consumes every field of the profile and is the canonical string a
    /// live `tls.peet.ws`/WAF capture is compared against in full (not just the
    /// SETTINGS prefix). Example (Firefox): `1:65536;2:0;4:131072;5:16384|
    /// 12517377|0|m,p,a,s`.
    #[must_use]
    pub fn akamai_fingerprint(&self) -> String {
        let settings = self
            .settings
            .iter()
            .map(|(id, value)| format!("{id}:{value}"))
            .collect::<Vec<_>>()
            .join(";");
        format!(
            "{settings}|{}|{}|{}",
            self.initial_window_increment, self.priority, self.pseudo_header_order
        )
    }
}

/// Chrome and Edge HTTP/2 SETTINGS profile.
///
/// Pseudo-header order `m,a,s,p` and no standalone PRIORITY frame (`0`), the
/// shape every bundled `chrome_tls` snapshot also carries, so the structured
/// model and the flat Chrome catalogue render the same Akamai string.
pub const CHROME_H2: H2Profile = H2Profile {
    family: "chrome",
    settings: &[(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)],
    initial_window_increment: 15_663_105,
    priority: "0",
    pseudo_header_order: "m,a,s,p",
};

/// Firefox HTTP/2 SETTINGS profile.
///
/// Setting `2` (ENABLE_PUSH) `= 0` is emitted explicitly, modern Firefox
/// disables server push, and a live `tls.peet.ws` capture of reynard/stock
/// FF-150 shows the full Akamai fingerprint
/// `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`. The model omitting `2:0`
/// was a real discrepancy the `tls_fingerprint` model-vs-engine differential
/// (G066) catches; the SETTINGS order matches the wire (`1,2,4,5`). FF-150 sends
/// no standalone PRIORITY frame on open (`0`), older Firefox sent `3:0:0:201`,
/// which is what the versioned `firefox-131` catalogue entry still records, and
/// the pseudo-header order is `m,p,a,s`. Every segment here is wire-verified
/// against reynard by `tls_fingerprint::reynard_h2_fingerprint_matches_guise_model`.
pub const FIREFOX_H2: H2Profile = H2Profile {
    family: "firefox",
    settings: &[(1, 65_536), (2, 0), (4, 131_072), (5, 16_384)],
    initial_window_increment: 12_517_377,
    priority: "0",
    pseudo_header_order: "m,p,a,s",
};

/// Safari HTTP/2 SETTINGS profile.
///
/// Pseudo-header order `m,s,p,a` (the Darwin/WebKit order, distinct from both
/// Chrome and Firefox) and no standalone PRIORITY frame (`0`).
pub const SAFARI_H2: H2Profile = H2Profile {
    family: "safari",
    settings: &[(3, 100), (4, 2_097_152), (8, 1)],
    initial_window_increment: 10_485_760,
    priority: "0",
    pseudo_header_order: "m,s,p,a",
};

/// Resolve the coherent `(HeaderOrder, H2Profile)` pair for a canonical browser profile.
#[must_use]
pub fn pair_for_profile(profile: StealthProfile) -> Option<(HeaderOrder, H2Profile)> {
    match profile {
        StealthProfile::ChromeWindowsStable
        | StealthProfile::ChromeWindowsLegacy96
        | StealthProfile::ChromeMacStable
        | StealthProfile::EdgeWindowsStable
        | StealthProfile::ChromeAndroid
        | StealthProfile::ChromeLinux
        | StealthProfile::BraveWindows
        | StealthProfile::OperaWindows
        | StealthProfile::SamsungInternetAndroid => Some((CHROME_HEADER_ORDER, CHROME_H2)),
        StealthProfile::FirefoxLinux
        | StealthProfile::FirefoxWindows
        | StealthProfile::FirefoxMacStable => Some((FIREFOX_HEADER_ORDER, FIREFOX_H2)),
        StealthProfile::SafariIphone
        | StealthProfile::SafariIpad
        | StealthProfile::SafariMacStable => Some((SAFARI_HEADER_ORDER, SAFARI_H2)),
        StealthProfile::Ie11Windows => None,
        _ => None,
    }
}

/// Resolve the coherent `(HeaderOrder, H2Profile)` pair for a browser alias.
#[must_use]
pub fn pair_for_name(name: &str) -> Option<(HeaderOrder, H2Profile)> {
    let key = name.to_ascii_lowercase();
    if let Some(profile) = named_profile(&key) {
        if let Some(pair) = pair_for_profile(profile) {
            return Some(pair);
        }
    }

    if key.starts_with("chrome") || key.starts_with("edge") {
        return Some((CHROME_HEADER_ORDER, CHROME_H2));
    }
    if key.starts_with("firefox") {
        return Some((FIREFOX_HEADER_ORDER, FIREFOX_H2));
    }
    if key.starts_with("safari") {
        return Some((SAFARI_HEADER_ORDER, SAFARI_H2));
    }
    None
}

impl HeaderOrder {
    /// Reshape a header bag to this browser family's canonical insertion order.
    ///
    /// Slot matching is case-insensitive, caller casing is preserved, duplicate
    /// headers retain relative order, and non-slot headers are appended in input
    /// order after the browser-shaped block.
    #[must_use]
    pub fn apply_in_order(&self, headers: Vec<(String, String)>) -> Vec<(String, String)> {
        let mut by_name: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut input_order: Vec<String> = Vec::new();
        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            input_order.push(lower.clone());
            by_name.entry(lower).or_default().push((name, value));
        }

        let mut out = Vec::new();
        let mut consumed = HashSet::new();
        for slot in self.slots {
            let slot_lower = slot.to_ascii_lowercase();
            if let Some(entries) = by_name.remove(&slot_lower) {
                out.extend(entries);
                consumed.insert(slot_lower);
            }
        }

        let mut seen = HashSet::new();
        for lower in input_order {
            if consumed.contains(&lower) || !seen.insert(lower.clone()) {
                continue;
            }
            if let Some(entries) = by_name.remove(&lower) {
                out.extend(entries);
            }
        }
        out
    }
}
