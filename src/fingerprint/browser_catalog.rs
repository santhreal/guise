//! Browser profile catalogue for request header stamping.
//!
//! This module preserves the lightweight `(name, header facts)` API used by
//! WAF tooling while delegating canonical browser values and ordered headers to
//! the shared stealth profile catalogue.

use crate::fingerprint::{profile_facts, StealthProfile};
use crate::http::headers::browser_headers;
use crate::rotation::named_profile;

/// The canonical browser header projection. Re-exported from `stealth-profiles`
/// (see [`guise_profiles::HeaderProfile`]): `browser_catalog` is a thin
/// catalog + selector layer over the one shared type, not a second definition.
pub use guise_profiles::HeaderProfile;

/// Built-in browser profiles.
pub const PROFILES: &[HeaderProfile] = &[
    canonical_profile("chrome-windows", StealthProfile::ChromeWindowsStable),
    canonical_profile("chrome-mac", StealthProfile::ChromeMacStable),
    canonical_profile("firefox-windows", StealthProfile::FirefoxWindows),
    canonical_profile("firefox-macos", StealthProfile::FirefoxMacStable),
    canonical_profile("firefox-linux", StealthProfile::FirefoxLinux),
    canonical_profile("safari-mac", StealthProfile::SafariMacStable),
    canonical_profile("edge-windows", StealthProfile::EdgeWindowsStable),
];

const fn canonical_profile(name: &'static str, stealth_profile: StealthProfile) -> HeaderProfile {
    let facts = profile_facts(stealth_profile);
    HeaderProfile {
        name,
        user_agent: facts.user_agent,
        accept: facts.accept,
        accept_language: facts.accept_language,
        accept_encoding: facts.accept_encoding,
        sec_fetch_site: "none",
        sec_fetch_mode: "navigate",
        sec_fetch_dest: "document",
    }
}

/// Select a random browser profile using the process RNG.
#[must_use]
pub fn random_profile() -> Option<&'static HeaderProfile> {
    crate::choice::random_item(PROFILES)
}

/// Select a browser profile deterministically from `seed`.
#[must_use]
pub fn seeded_profile(seed: u64) -> Option<&'static HeaderProfile> {
    if PROFILES.is_empty() {
        return None;
    }
    let mixed = seed
        .wrapping_add(0x9e37_79b9_7f4a_7c15)
        .wrapping_mul(0x6eed_0e9d_a4d9_4a4f);
    let index = (mixed as usize) % PROFILES.len();
    Some(&PROFILES[index])
}

/// Apply a browser profile to a request's headers.
pub fn apply_profile(headers: &mut Vec<(String, String)>, profile: &HeaderProfile) {
    headers.retain(|(key, _)| {
        let lower = key.to_ascii_lowercase();
        lower != "user-agent"
            && lower != "accept"
            && lower != "accept-language"
            && lower != "accept-encoding"
            && lower != "upgrade-insecure-requests"
            && !lower.starts_with("sec-fetch")
            && !lower.starts_with("sec-ch-ua")
    });

    if let Some(canonical) = named_profile(profile.name) {
        headers.extend(
            browser_headers(canonical)
                .into_iter()
                .map(|header| (header.name.to_string(), header.value)),
        );
        return;
    }

    apply_legacy_profile(headers, profile);
}

fn apply_legacy_profile(headers: &mut Vec<(String, String)>, profile: &HeaderProfile) {
    headers.push(("User-Agent".into(), profile.user_agent.into()));
    headers.push(("Accept".into(), profile.accept.into()));
    headers.push(("Accept-Language".into(), profile.accept_language.into()));
    headers.push(("Accept-Encoding".into(), profile.accept_encoding.into()));
    headers.push(("Sec-Fetch-Site".into(), profile.sec_fetch_site.into()));
    headers.push(("Sec-Fetch-Mode".into(), profile.sec_fetch_mode.into()));
    headers.push(("Sec-Fetch-Dest".into(), profile.sec_fetch_dest.into()));
}

#[cfg(test)]
#[path = "browser_catalog/tests.rs"]
mod tests;
