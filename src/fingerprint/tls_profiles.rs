//! TLS ClientHello profile catalogue for browser-shaped transports.
//!
//! These profiles describe the cipher, extension, curve, ALPN, signature
//! algorithm, and GREASE choices that higher-level transport code can use when
//! selecting or validating a browser-grade TLS impersonation path.
//!
//! # Role among the three TLS catalogues (G010, one taxonomy, distinct roles)
//!
//! guise carries three TLS reference catalogues. They are NOT duplicates; each
//! owns a distinct job, and none of them emits a real ClientHello on the wire
//! the actual browser-traffic handshake is NSS-native (reynard) and the
//! non-browser handshake is wreq/boring via [`ImpersonateProfile`]:
//!
//! - **`tls_profiles::TlsProfile` (this module)**: structured ClientHello field
//!   shapes ([`ClientHelloFields`] inputs) keyed by a named client family, plus
//!   the [`StealthProfile`] → [`ImpersonateProfile`] mapping. Consumed by the
//!   coherence gate and JA3/JA4 *computation* helpers; it is the structured
//!   source, the other two are flat string catalogues.
//! - **`fingerprint::chrome_tls`**: versioned Chrome *diagnostic snapshots*
//!   (full JA3 string + MD5 hash + H2 fingerprint per Chrome major/platform).
//!   For comparing an *observed* Chrome transport against a known shape.
//! - **`fingerprint::tls_targets`**: versioned per-*label* targets
//!   (`chrome-146-linux`, `firefox-150-linux`, `firefox-151-linux`) carrying the
//!   full JA3 + JA4 + Akamai-H2 + peet strings. For selecting/validating a
//!   transport against a specific published target.

use crate::choice::random_item;
use crate::fingerprint::ja3::{compute_ja3, compute_ja4, ClientHelloFields};
use crate::fingerprint::StealthProfile;
use crate::rotation::named_profile;

#[cfg(feature = "http")]
use scanclient::tls_impersonate::ImpersonateProfile;

/// A TLS fingerprint profile that mimics a specific browser or client family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsProfile {
    /// Human-readable name.
    pub name: &'static str,
    /// Legacy TLS version in the ClientHello.
    pub tls_version: u16,
    /// Cipher suites to offer, in exact client order.
    pub cipher_suites: &'static [u16],
    /// TLS extensions to include, in exact client order.
    pub extensions: &'static [u16],
    /// Supported groups.
    pub elliptic_curves: &'static [u16],
    /// EC point formats.
    pub ec_point_formats: &'static [u8],
    /// ALPN protocols to advertise.
    pub alpn_protocols: &'static [&'static str],
    /// Self-checksum: the MD5 of THIS profile's own computed JA3 string
    /// (`md5(compute_ja3_string(self))`), a regression anchor that forces an
    /// update whenever the cipher/extension/curve fields change. Locked by
    /// `expected_ja3_equals_md5_of_computed_ja3_string`.
    ///
    /// For the *simplified* profiles (the coherence-gate approximations whose
    /// field lists are not a full wire capture) this is ONLY a self-checksum, not
    /// a real-browser target; verified real-browser JA3 hashes for those live in
    /// `chrome_tls` / `tls_targets`. For a *wire-accurate* profile
    /// (`FIREFOX_150`, whose fields ARE a measured ClientHello) the
    /// self-checksum and the real measured JA3 CONVERGE (the value here is both).
    pub expected_ja3: &'static str,
    /// Signature algorithms to advertise.
    pub signature_algorithms: &'static [u16],
    /// Whether to include GREASE values.
    pub include_grease: bool,
    /// TLS versions offered in the `supported_versions` extension (0x002b),
    /// highest first. JA4 derives its version digit from the highest entry here;
    /// every modern browser pins the legacy [`Self::tls_version`] to 0x0303 but
    /// negotiates TLS 1.3 via this list.
    pub supported_versions: &'static [u16],
}

mod catalog;
use catalog::{ALL_PROFILES, CHROME_120, CHROME_146, FIREFOX_150, SAFARI_18, SAFARI_IOS_18};

const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn random_grease() -> u16 {
    random_item(GREASE_VALUES)
        .copied()
        .unwrap_or(GREASE_VALUES[0])
}

#[cfg(feature = "http")]
const CHROME_LEGACY_IMPERSONATE_PROFILES: &[ImpersonateProfile] = &[ImpersonateProfile::Chrome120];
#[cfg(feature = "http")]
const CHROMIUM_IMPERSONATE_PROFILES: &[ImpersonateProfile] =
    &[ImpersonateProfile::Chrome131, ImpersonateProfile::Chrome120];
#[cfg(feature = "http")]
const EDGE_IMPERSONATE_PROFILES: &[ImpersonateProfile] = &[ImpersonateProfile::Edge131];
#[cfg(feature = "http")]
const FIREFOX_IMPERSONATE_PROFILES: &[ImpersonateProfile] = &[ImpersonateProfile::Firefox133];
#[cfg(feature = "http")]
const SAFARI_IMPERSONATE_PROFILES: &[ImpersonateProfile] = &[
    ImpersonateProfile::Safari18,
    ImpersonateProfile::SafariIpad18,
    ImpersonateProfile::Safari17_5,
];
#[cfg(feature = "http")]
const CHROMIUM_ALT_IMPERSONATE_PROFILES: &[ImpersonateProfile] = &[
    ImpersonateProfile::Chrome131,
    ImpersonateProfile::Chrome120,
    ImpersonateProfile::Edge131,
];
#[cfg(feature = "http")]
const NO_IMPERSONATE_PROFILES: &[ImpersonateProfile] = &[];

/// Return all available TLS profiles.
#[must_use]
pub fn profiles() -> &'static [TlsProfile] {
    ALL_PROFILES
}

/// Find the closest pure TLS ClientHello catalogue entry for a stealth browser profile.
#[must_use]
pub const fn profile_for_stealth_profile(profile: StealthProfile) -> Option<&'static TlsProfile> {
    match profile {
        // Every modern-stable Chromium persona, including Edge, Brave, Opera, and
        // Samsung Internet, shares the measured byte-accurate Chrome-146
        // ClientHello. Chromium's BoringSSL stack (like Firefox's NSS) emits an
        // OS-independent ClientHello for a given version, so the one measured shape
        // is correct for Windows/Linux/Mac/Android and all Chromium derivatives.
        // Edge has no distinct measured capture on this fleet; using the Chrome-146
        // shape is honest because Edge is Chromium-derived, whereas the old
        // `EDGE_120` placeholder lifted simplified Chrome slices and produced a JA4
        // that did not collide with any populated real-browser cluster.
        StealthProfile::ChromeWindowsStable
        | StealthProfile::ChromeLinux
        | StealthProfile::ChromeAndroid
        | StealthProfile::ChromeMacStable
        | StealthProfile::EdgeWindowsStable
        | StealthProfile::BraveWindows
        | StealthProfile::OperaWindows
        | StealthProfile::SamsungInternetAndroid => Some(&CHROME_146),
        // The explicit legacy persona keeps the older shape.
        StealthProfile::ChromeWindowsLegacy96 => Some(&CHROME_120),
        // Both desktop-Firefox personas share the OS-independent, version-stable
        // FF-150 ClientHello: Firefox's NSS emits identical bytes on Linux/Windows
        // for a given version, so a per-OS TLS split would itself be unreal. The
        // persona UA major (Firefox/150) now MATCHES this profile's version, so the
        // HTTP-client emits a coherent UA-vs-JA3 pair; FF ClientHello is stable
        // across 132→150. The OS distinction lives in the UA/platform, not here.
        StealthProfile::FirefoxLinux
        | StealthProfile::FirefoxWindows
        | StealthProfile::FirefoxMacStable => Some(&FIREFOX_150),
        // iPhone/iPad personas carry the measured iOS Safari-18 coretls shape
        // byte-identical to the macOS `SAFARI_18` wire (Apple ships one coretls per
        // Safari major across all OSes), but named for iOS so the persona's TLS
        // profile name stays platform-coherent. Replaces the old Chrome-borrowed
        // `SAFARI_IOS_17` placeholder.
        StealthProfile::SafariIphone | StealthProfile::SafariIpad => Some(&SAFARI_IOS_18),
        StealthProfile::SafariMacStable => Some(&SAFARI_18),
        StealthProfile::Ie11Windows => None,
        _ => None,
    }
}

/// Return the default wire impersonation profile for a stealth browser profile.
///
/// This is the scanner-backed `wreq`/BoringSSL identity, not the pure JA3
/// catalogue entry returned by [`profile_for_stealth_profile`].
#[cfg(feature = "http")]
#[must_use]
pub const fn default_impersonate_profile_for_stealth_profile(
    profile: StealthProfile,
) -> ImpersonateProfile {
    match profile {
        StealthProfile::ChromeWindowsLegacy96 => ImpersonateProfile::Chrome120,
        StealthProfile::Ie11Windows => ImpersonateProfile::Chrome120,
        StealthProfile::EdgeWindowsStable => ImpersonateProfile::Edge131,
        StealthProfile::FirefoxLinux
        | StealthProfile::FirefoxWindows
        | StealthProfile::FirefoxMacStable => ImpersonateProfile::Firefox133,
        // Default wire identity tracks the measured pure-catalogue profile major
        // (18, not the older 17.5): macOS Safari → desktop Safari18; iPhone/iPad →
        // the mobile SafariIpad18 emulation (its ClientHello is byte-identical to
        // desktop but it carries the iOS UA), so UA and TLS stay platform-coherent.
        StealthProfile::SafariMacStable => ImpersonateProfile::Safari18,
        StealthProfile::SafariIphone | StealthProfile::SafariIpad => {
            ImpersonateProfile::SafariIpad18
        }
        StealthProfile::ChromeWindowsStable
        | StealthProfile::ChromeMacStable
        | StealthProfile::ChromeAndroid
        | StealthProfile::ChromeLinux
        | StealthProfile::BraveWindows
        | StealthProfile::OperaWindows
        | StealthProfile::SamsungInternetAndroid => ImpersonateProfile::Chrome131,
        _ => ImpersonateProfile::Chrome131,
    }
}

/// Return every wire impersonation profile compatible with a stealth browser profile.
#[cfg(feature = "http")]
#[must_use]
pub const fn compatible_impersonate_profiles_for_stealth_profile(
    profile: StealthProfile,
) -> &'static [ImpersonateProfile] {
    match profile {
        StealthProfile::ChromeWindowsLegacy96 => CHROME_LEGACY_IMPERSONATE_PROFILES,
        StealthProfile::Ie11Windows => NO_IMPERSONATE_PROFILES,
        StealthProfile::ChromeWindowsStable
        | StealthProfile::ChromeMacStable
        | StealthProfile::ChromeAndroid
        | StealthProfile::ChromeLinux
        | StealthProfile::SamsungInternetAndroid => CHROMIUM_IMPERSONATE_PROFILES,
        StealthProfile::EdgeWindowsStable => EDGE_IMPERSONATE_PROFILES,
        StealthProfile::FirefoxLinux
        | StealthProfile::FirefoxWindows
        | StealthProfile::FirefoxMacStable => FIREFOX_IMPERSONATE_PROFILES,
        StealthProfile::SafariIphone
        | StealthProfile::SafariIpad
        | StealthProfile::SafariMacStable => SAFARI_IMPERSONATE_PROFILES,
        StealthProfile::BraveWindows | StealthProfile::OperaWindows => {
            CHROMIUM_ALT_IMPERSONATE_PROFILES
        }
        _ => NO_IMPERSONATE_PROFILES,
    }
}

/// Check whether a scanner-backed TLS impersonation profile matches a stealth browser profile.
#[cfg(feature = "http")]
#[must_use]
pub fn impersonate_profile_matches_stealth_profile(
    browser: StealthProfile,
    tls: ImpersonateProfile,
) -> bool {
    compatible_impersonate_profiles_for_stealth_profile(browser).contains(&tls)
}

/// The browser family (`"chrome"`/`"firefox"`/`"safari"`) a wire impersonation
/// profile belongs to, or `None` for non-browser clients (OkHttp) and any
/// future profile not yet classified. `ImpersonateProfile` is `#[non_exhaustive]`.
///
/// Lets the session-coherence gate cross-check the TLS layer's family against a
/// persona's UA browser family (the "TLS says Firefox, UA says Chrome" tell).
#[cfg(feature = "http")]
#[must_use]
pub const fn impersonate_profile_family(profile: ImpersonateProfile) -> Option<&'static str> {
    match profile {
        ImpersonateProfile::Chrome120
        | ImpersonateProfile::Chrome131
        | ImpersonateProfile::Edge131 => Some("chrome"),
        ImpersonateProfile::Firefox133 => Some("firefox"),
        ImpersonateProfile::Safari17_5
        | ImpersonateProfile::Safari18
        | ImpersonateProfile::SafariIpad18 => Some("safari"),
        _ => None,
    }
}

/// Find a TLS profile by shared stealth profile name first, then by legacy
/// case-insensitive substring match on the catalogue entry name.
#[must_use]
pub fn profile_for(browser: &str) -> Option<&'static TlsProfile> {
    let browser = browser.trim();
    if browser.is_empty() {
        return None;
    }
    if let Some(profile) = named_profile(browser) {
        return profile_for_stealth_profile(profile);
    }
    let lower = browser.to_ascii_lowercase();
    ALL_PROFILES
        .iter()
        .find(|profile| profile.name.to_ascii_lowercase().contains(&lower))
}

/// Pick a random TLS profile.
#[must_use]
pub fn random_profile() -> Option<&'static TlsProfile> {
    random_item(ALL_PROFILES)
}

/// Generate the cipher-suite list for a profile, with GREASE when applicable.
#[must_use]
pub fn build_cipher_suites(profile: &TlsProfile) -> Vec<u16> {
    let mut suites = Vec::with_capacity(profile.cipher_suites.len() + 1);
    if profile.include_grease {
        suites.push(random_grease());
    }
    suites.extend_from_slice(profile.cipher_suites);
    suites
}

/// Generate the extension list for a profile, with GREASE when applicable.
#[must_use]
pub fn build_extensions(profile: &TlsProfile) -> Vec<u16> {
    let mut extensions = Vec::with_capacity(profile.extensions.len() + 2);
    if profile.include_grease {
        extensions.push(random_grease());
    }
    extensions.extend_from_slice(profile.extensions);
    if profile.include_grease {
        extensions.push(random_grease());
    }
    extensions
}

/// Generate the supported-groups list for a profile, with GREASE when applicable.
#[must_use]
pub fn build_supported_groups(profile: &TlsProfile) -> Vec<u16> {
    let mut groups = Vec::with_capacity(profile.elliptic_curves.len() + 1);
    if profile.include_grease {
        groups.push(random_grease());
    }
    groups.extend_from_slice(profile.elliptic_curves);
    groups
}

/// Convert a profile to the shared stealth JA3/JA4 input shape.
#[must_use]
pub fn client_hello_fields(profile: &TlsProfile) -> ClientHelloFields {
    ClientHelloFields {
        version: profile.tls_version,
        cipher_suites: profile.cipher_suites.to_vec(),
        extensions: profile.extensions.to_vec(),
        supported_groups: profile.elliptic_curves.to_vec(),
        ec_point_formats: profile.ec_point_formats.to_vec(),
        alpn: profile
            .alpn_protocols
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect(),
        signature_algorithms: profile.signature_algorithms.to_vec(),
        supported_versions: profile.supported_versions.to_vec(),
    }
}

/// Compute the canonical JA3 string for a profile.
#[must_use]
pub fn compute_ja3_string(profile: &TlsProfile) -> String {
    compute_ja3(&client_hello_fields(profile))
}

/// Compute the JA4 fingerprint string for a profile.
///
/// Symmetric with [`compute_ja3_string`]. The JA4 version digit reflects the
/// profile's `supported_versions` (TLS 1.3 → `t13`), not the legacy 0x0303 the
/// ClientHello pins for compatibility.
#[must_use]
pub fn compute_ja4_string(profile: &TlsProfile) -> String {
    compute_ja4(&client_hello_fields(profile))
}

/// Summary of the profile's distinguishing TLS properties.
#[must_use]
pub fn profile_summary(profile: &TlsProfile) -> String {
    format!(
        "{}: TLS {:#06x}, {} ciphers, {} extensions, GREASE={}, ALPN=[{}]",
        profile.name,
        profile.tls_version,
        profile.cipher_suites.len(),
        profile.extensions.len(),
        profile.include_grease,
        profile.alpn_protocols.join(", "),
    )
}

#[cfg(test)]
#[path = "tls_profiles/tests.rs"]
mod tests;
