//! Persona rarity scoring (G104).
//!
//! Anti-bot systems track visitors partly by how *unique* their fingerprint is.
//! A persona that no real user shares is a tell, even if every individual value
//! is "plausible". The rarity score estimates how common a shipped persona is
//! in the real world, so selection logic (G231) can prefer modal, populated
//! buckets over uncrowded ones.
//!
//! The score is a unitless 1-100 rank derived from public browser-market-share
//! data and the relative frequency of the OS/hardware combination. It is NOT a
//! precise population percentage; it is a stable ordinal for persona selection.

use guise_profiles::StealthProfile;

/// Rarity score for a shipped persona. Higher means more common / less unique.
///
/// The scale is ordinal, not a percentage of real users. A score of 100 is the
/// most modal shipped persona; 1 is the rarest.
pub fn rarity_score(profile: StealthProfile) -> u32 {
    match profile {
        // Chrome on Windows is the modal desktop browser by market share.
        StealthProfile::ChromeWindowsStable => 100,
        // Firefox on Linux and Windows are large, well-populated buckets.
        StealthProfile::FirefoxLinux => 85,
        StealthProfile::FirefoxWindows => 84,
        // Chrome on macOS and Linux are common but smaller than Windows Chrome.
        StealthProfile::ChromeMacStable => 70,
        StealthProfile::ChromeLinux => 68,
        // Safari on macOS and iOS are modal on Apple hardware.
        StealthProfile::SafariMacStable => 65,
        StealthProfile::SafariIphone => 60,
        StealthProfile::SafariIpad => 55,
        // Edge on Windows is a common Chromium derivative.
        StealthProfile::EdgeWindowsStable => 50,
        // Firefox on macOS is a smaller but real bucket.
        StealthProfile::FirefoxMacStable => 45,
        // Android Chrome/Samsung are common globally but more homogeneous.
        StealthProfile::ChromeAndroid => 40,
        StealthProfile::SamsungInternetAndroid => 30,
        // Brave/Opera are niche desktop browsers.
        StealthProfile::BraveWindows => 20,
        StealthProfile::OperaWindows => 15,
        // Legacy IE11 is extremely rare today and should almost never be chosen
        // unless the operator explicitly asks for it.
        StealthProfile::Ie11Windows => 5,
        // The legacy Chrome 96 persona is rare because it represents an old
        // browser version.
        StealthProfile::ChromeWindowsLegacy96 => 10,
        // Future personas default to a low-but-non-zero score until their
        // real-world frequency is measured.
        _ => 10,
    }
}

/// Whether the persona is considered "modal", in the top half of the rarity
/// distribution. Selection logic can use this as a cheap filter.
pub fn is_modal(profile: StealthProfile) -> bool {
    rarity_score(profile) >= 60
}

/// Iterator over all shipped personas sorted from most common to rarest.
pub fn personas_by_rarity() -> impl Iterator<Item = (StealthProfile, u32)> {
    let mut v: Vec<_> = guise_profiles::ALL_PROFILES
        .iter()
        .copied()
        .map(|p| (p, rarity_score(p)))
        .collect();
    v.sort_by_key(|p| std::cmp::Reverse(p.1));
    v.into_iter()
}

#[cfg(test)]
#[path = "rarity/tests.rs"]
mod tests;
