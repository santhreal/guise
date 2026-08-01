//! [`ProfileBundle`] - browser fingerprint + optional TLS impersonation profile.

#[cfg(feature = "tier-b-toml")]
use std::path::Path;

use thiserror::Error;

use super::profiles::{profile_to_overrides, StealthProfile, DEFAULT_STEALTH_PROFILE};

#[cfg(feature = "http")]
use crate::fingerprint::tls_profiles::{
    default_impersonate_profile_for_stealth_profile, impersonate_profile_matches_stealth_profile,
};
#[cfg(feature = "tier-b-toml")]
use guise_profiles as profile_catalog;
#[cfg(feature = "http")]
use scanclient::tls_impersonate::ImpersonateProfile;

/// A coherent stealth configuration spanning browser JS fingerprint and TLS ClientHello.
///
/// G124 / persona lock: the bundle is immutable once assembled. Every field is
/// `pub` but there are no `&mut self` methods, the only way to change a persona
/// mid-session is to build a new bundle. This guarantees that the identity
/// injected at launch cannot drift silently as the session progresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileBundle {
    /// The browser-side JS fingerprint profile (navigator / WebGL / screen overrides).
    pub browser: StealthProfile,
    /// The TLS ClientHello profile that must match `browser` on the wire.
    #[cfg(feature = "http")]
    pub tls: ImpersonateProfile,
}

/// Errors loading or validating profile bundles.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    /// A bundle's surfaces contradict each other (e.g. a Windows UA with a
    /// macOS WebGL renderer) (caught by `validate_*` before it reaches a WAF).
    #[error("profile bundle is internally inconsistent: {0}")]
    Incoherent(String),
    #[error("failed to read profile TOML: {0}")]
    #[cfg(feature = "tier-b-toml")]
    /// Reading a Tier-B profile TOML file failed.
    TomlRead(String),
    #[error("failed to parse profile TOML: {0}")]
    #[cfg(feature = "tier-b-toml")]
    /// Parsing or validating a Tier-B profile TOML file failed.
    TomlParse(String),
}

impl ProfileBundle {
    /// Build a coherent bundle for any built-in browser profile, validating
    /// browser-side coherence at construction time (G086).
    ///
    /// Panics if the profile is internally incoherent; use
    /// [`Self::try_for_browser`] for a fallible constructor.
    #[must_use]
    #[allow(clippy::expect_used)] // a built-in profile is validated at test time
    pub fn for_browser(browser: StealthProfile) -> Self {
        Self::try_for_browser(browser).expect("built-in browser profile must be coherent")
    }

    /// Fallible version of [`Self::for_browser`]: every bundle is validated on
    /// build so an incoherent persona cannot be assembled silently.
    ///
    /// When the `http` feature is active this asserts **full** coherence, including
    /// browser/TLS family agreement (G093). Legacy personas with no compatible
    /// TLS profile (e.g. IE11) are rejected here rather than silently paired with
    /// a mismatched ClientHello.
    pub fn try_for_browser(browser: StealthProfile) -> Result<Self, ProfileError> {
        let bundle = Self {
            browser,
            #[cfg(feature = "http")]
            tls: default_impersonate_profile_for_stealth_profile(browser),
        };
        #[cfg(feature = "http")]
        bundle.validate_full_coherence()?;
        #[cfg(not(feature = "http"))]
        bundle.validate_browser_coherence()?;
        Ok(bundle)
    }

    /// Build the fleet-owned default stealth bundle.
    #[must_use]
    pub fn default_stealth() -> Self {
        Self::for_browser(DEFAULT_STEALTH_PROFILE)
    }

    /// Chrome 131-class fingerprint on macOS + matching TLS profile.
    #[must_use]
    pub fn chrome_131_macos() -> Self {
        Self::for_browser(StealthProfile::ChromeMacStable)
    }

    /// Chrome 131-class fingerprint on Windows + matching TLS profile.
    #[must_use]
    pub fn chrome_131_windows() -> Self {
        Self::for_browser(StealthProfile::ChromeWindowsStable)
    }

    /// Firefox 133 fingerprint on Linux desktop + matching TLS profile.
    #[must_use]
    pub fn firefox_133() -> Self {
        Self::for_browser(StealthProfile::FirefoxLinux)
    }

    /// Firefox 133 fingerprint on Windows desktop + matching TLS profile.
    #[must_use]
    pub fn firefox_133_windows() -> Self {
        Self::for_browser(StealthProfile::FirefoxWindows)
    }

    /// Safari 17.5 fingerprint (macOS desktop) + matching TLS profile.
    #[must_use]
    pub fn safari_17_5() -> Self {
        Self::for_browser(StealthProfile::SafariMacStable)
    }

    /// Edge 131 on Windows + matching TLS profile.
    #[must_use]
    pub fn edge_131() -> Self {
        Self::for_browser(StealthProfile::EdgeWindowsStable)
    }

    /// Generate a deterministic, oracle-valid bundle from a seed (G088/G314).
    ///
    /// The seed selects from the rotation pool, personas that have a matching
    /// TLS impersonation profile, so the resulting bundle is guaranteed to pass
    /// both browser and full wire coherence. The same seed always yields the same
    /// bundle, making it usable for per-account persona pinning and incident
    /// triage.
    ///
    /// # Example
    ///
    /// ```
    /// use guise::ProfileBundle;
    ///
    /// let a = ProfileBundle::from_seed(42);
    /// let b = ProfileBundle::from_seed(42);
    /// assert_eq!(a.browser, b.browser);
    /// assert!(a.validate_browser_coherence().is_ok());
    /// ```
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        use super::profiles::ROTATION_PROFILES;
        let mixed = seed
            .wrapping_add(0x9e37_79b9_7f4a_7c15)
            .wrapping_mul(0x6eed_0e9d_a4d9_4a4f);
        let idx = (mixed as usize) % ROTATION_PROFILES.len();
        Self::for_browser(ROTATION_PROFILES[idx])
    }

    /// Validate UA/platform/brands coherence inside the browser half.
    pub fn validate_browser_coherence(&self) -> Result<(), ProfileError> {
        validate_overrides(&profile_to_overrides(&self.browser))
    }

    /// Validate browser + TLS halves agree on browser family (Chrome vs Firefox vs Safari vs Edge).
    #[cfg(feature = "http")]
    pub fn validate_full_coherence(&self) -> Result<(), ProfileError> {
        self.validate_browser_coherence()?;
        validate_tls_family(self.browser, self.tls)
    }

    /// Load a Tier-B profile TOML from disk.
    #[cfg(feature = "tier-b-toml")]
    pub fn from_toml(path: &Path) -> Result<Self, ProfileError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| ProfileError::TomlRead(format!("{}: {e}", path.display())))?;
        let doc: TierBProfileDoc =
            toml::from_str(&raw).map_err(|e| ProfileError::TomlParse(e.to_string()))?;
        let browser = profile_catalog::named_profile(&doc.browser).ok_or_else(|| {
            ProfileError::TomlParse(format!("unknown browser profile {}", doc.browser))
        })?;
        #[cfg(feature = "http")]
        let tls = ImpersonateProfile::parse(&doc.tls)
            .map_err(|e| ProfileError::TomlParse(e.to_string()))?;
        let bundle = Self {
            browser,
            #[cfg(feature = "http")]
            tls,
        };
        #[cfg(feature = "http")]
        bundle.validate_full_coherence()?;
        #[cfg(not(feature = "http"))]
        bundle.validate_browser_coherence()?;
        Ok(bundle)
    }
}

/// Internal coherence checks on materialised overrides (property-test target).
pub fn validate_overrides(ov: &super::profiles::ProfileOverrides) -> Result<(), ProfileError> {
    if ov.user_agent.contains("Windows") && ov.platform != "Win32" {
        return Err(ProfileError::Incoherent(format!(
            "UA claims Windows but platform is {}",
            ov.platform
        )));
    }
    // iOS Safari UAs contain "like Mac OS X" but platform is iPhone/iPad.
    let ios_ua = ov.user_agent.contains("iPhone") || ov.user_agent.contains("iPad");
    if ov.user_agent.contains("Mac OS X") && !ios_ua && ov.platform != "MacIntel" {
        return Err(ProfileError::Incoherent(format!(
            "UA claims macOS desktop but platform is {}",
            ov.platform
        )));
    }
    // iOS: the macOS rule above *exempts* an iPhone/iPad UA (it carries
    // "like Mac OS X") from the MacIntel requirement, close the hole that
    // exemption opens by positively pinning the iOS platform. Apple's
    // navigator.platform is "iPhone" / "iPad" (NOT "MacIntel"); the shipped
    // SafariIphone/SafariIpad personas use exactly those, so a mismatch is a tell.
    if ios_ua && ov.platform != "iPhone" && ov.platform != "iPad" {
        return Err(ProfileError::Incoherent(format!(
            "iOS UA (iPhone/iPad) but platform is {} (expected iPhone or iPad)",
            ov.platform
        )));
    }
    if ov.user_agent.contains("Android") && !ov.mobile {
        return Err(ProfileError::Incoherent(
            "Android UA requires mobile=true".into(),
        ));
    }
    // Any Linux-based UA, desktop Linux ("X11; Linux ...") OR Android
    // ("Linux; Android ..."), must report a "Linux"-prefixed navigator.platform:
    // "Linux x86_64"/"Linux i686" on desktop, "Linux armv8l"/"Linux aarch64" on
    // Android. A Linux UA paired with Win32/MacIntel is the mirror of the
    // Windows/macOS tells and previously slipped through (the gate validated
    // Windows and macOS UA↔platform but had no Linux rule; Android's platform was
    // unchecked entirely, only its mobile flag was). We pin the "Linux" PREFIX
    // only, not the arch, because Android-x86 builds exist and requiring arm would
    // false-positive. (Android additionally requires mobile=true, checked above.)
    if ov.user_agent.contains("Linux") && !ov.platform.starts_with("Linux") {
        return Err(ProfileError::Incoherent(format!(
            "UA is Linux-based but platform is {} (expected a Linux-prefixed navigator.platform)",
            ov.platform
        )));
    }
    // WebGL vendor/renderer (UNMASKED_VENDOR_WEBGL / UNMASKED_RENDERER_WEBGL) is a
    // heavily-weighted fingerprint signal: CreepJS and friends key directly on
    // these strings. An Apple GPU, reported raw by Safari ("Apple Inc." /
    // "Apple GPU" / "Apple M2") or ANGLE-wrapped by Chrome-on-Mac
    // ("Google Inc. (Apple)"), can physically only exist on Apple hardware. A
    // non-Apple navigator.platform claiming an Apple GPU is a glaring cross-surface
    // tell, so the gate must reject it. (Every shipped Apple-GPU persona is on
    // MacIntel/iPhone/iPad; no non-Apple persona carries "Apple" in its GPU
    // strings, so this never false-positives, verified by the all-persona sweep.)
    let claims_apple_gpu = ov.webgl_vendor.contains("Apple") || ov.webgl_renderer.contains("Apple");
    let apple_platform =
        ov.platform == "MacIntel" || ov.platform == "iPhone" || ov.platform == "iPad";
    if claims_apple_gpu && !apple_platform {
        return Err(ProfileError::Incoherent(format!(
            "WebGL claims an Apple GPU (vendor {:?}, renderer {:?}) but platform is {} \
             (Apple GPUs exist only on MacIntel/iPhone/iPad)",
            ov.webgl_vendor, ov.webgl_renderer, ov.platform
        )));
    }
    // The mirror of the Apple-GPU rule for the OTHER direction: a `Direct3D` /
    // `D3D11` renderer is the Windows ANGLE backend and physically exists only on
    // Windows, a non-Windows navigator.platform claiming it is the same
    // cross-surface tell (e.g. a MacIntel/Linux persona with
    // "ANGLE (NVIDIA, … Direct3D11 …)"). macOS uses Metal, Linux uses Mesa/OpenGL,
    // so every shipped Direct3D persona is Win32, this never false-positives
    // (verified by the all-persona sweep in tests/integration.rs).
    let claims_direct3d =
        ov.webgl_renderer.contains("Direct3D") || ov.webgl_renderer.contains("D3D11");
    if claims_direct3d && ov.platform != "Win32" {
        return Err(ProfileError::Incoherent(format!(
            "WebGL claims a Direct3D renderer ({:?}) but platform is {} \
             (Direct3D/D3D11 is the Windows ANGLE backend; macOS uses Metal, Linux Mesa/OpenGL)",
            ov.webgl_renderer, ov.platform
        )));
    }
    let chromium_ua = ov.user_agent.contains("Chrome/") || ov.user_agent.contains("Chromium");
    if chromium_ua && !ov.user_agent.contains("Firefox/") && ov.brands.is_empty() {
        return Err(ProfileError::Incoherent(
            "Chromium UA without userAgentData brands".into(),
        ));
    }
    if ov.user_agent.contains("Firefox/") && !ov.brands.is_empty() {
        return Err(ProfileError::Incoherent(
            "Firefox UA must not ship Client Hints brands".into(),
        ));
    }
    validate_brand_versions(ov)?;
    validate_timezone_geo(ov)?;
    Ok(())
}

/// Reject a persona whose pinned `timezone` belongs to a different country than
/// its primary `navigator.languages` implies, the "de-DE persona presenting an
/// `America/New_York` timezone" tell (R056). Defaulted timezones are coherent by
/// construction (`profile_to_overrides` derives them from the language); this
/// catches an operator-supplied [`with_timezone`](super::profiles::ProfileOverrides::with_timezone)
/// that does not match the persona's locale. Only fires when BOTH the language's
/// expected country and the timezone's country are in the geo catalogue and they
/// differ, an uncatalogued zone is not a *known* incoherence, so it is not
/// rejected here (no false positive on an exotic-but-valid zone).
fn validate_timezone_geo(ov: &super::profiles::ProfileOverrides) -> Result<(), ProfileError> {
    use super::geo_coherence::timezone_facts;
    use super::profiles::default_timezone_for_locale;
    let Some(primary) = ov.languages.first() else {
        return Ok(());
    };
    let expected_tz = default_timezone_for_locale(primary);
    let (Some(expected), Some(actual)) =
        (timezone_facts(expected_tz), timezone_facts(&ov.timezone))
    else {
        return Ok(());
    };
    if expected.country != actual.country {
        return Err(ProfileError::Incoherent(format!(
            "timezone {} (country {}) is incoherent with primary language {:?} (expects country {})",
            ov.timezone, actual.country, primary, expected.country
        )));
    }
    Ok(())
}

fn validate_brand_versions(ov: &super::profiles::ProfileOverrides) -> Result<(), ProfileError> {
    for (brand, version) in &ov.brands {
        if !version.chars().all(|c| c.is_ascii_digit()) {
            return Err(ProfileError::Incoherent(format!(
                "Client Hint brand {brand:?} has non-numeric version {version:?}"
            )));
        }
        let Some(expected) = expected_brand_major(&ov.user_agent, brand) else {
            continue;
        };
        if version != expected {
            return Err(ProfileError::Incoherent(format!(
                "Client Hint brand {brand:?} version {version} does not match UA major {expected}"
            )));
        }
    }
    Ok(())
}

fn expected_brand_major<'a>(ua: &'a str, brand: &str) -> Option<&'a str> {
    match brand {
        "Chromium" | "Google Chrome" | "Brave" => major_after(ua, "Chrome/"),
        "Microsoft Edge" => major_after(ua, "Edg/"),
        "Opera" => major_after(ua, "OPR/"),
        "Samsung Internet" => major_after(ua, "SamsungBrowser/"),
        _ => None,
    }
}

fn major_after<'a>(ua: &'a str, token: &str) -> Option<&'a str> {
    let after = ua.split_once(token)?.1;
    let major = after.split('.').next().unwrap_or(after);
    if major.is_empty() {
        None
    } else {
        Some(major)
    }
}

#[cfg(feature = "http")]
fn validate_tls_family(
    browser: StealthProfile,
    tls: ImpersonateProfile,
) -> Result<(), ProfileError> {
    if impersonate_profile_matches_stealth_profile(browser, tls) {
        Ok(())
    } else {
        Err(ProfileError::Incoherent(format!(
            "browser profile {browser:?} incompatible with TLS profile {tls:?}"
        )))
    }
}

#[cfg(feature = "tier-b-toml")]
#[derive(Debug, serde::Deserialize)]
struct TierBProfileDoc {
    browser: String,
    tls: String,
}

#[cfg(test)]
#[path = "bundle/tests.rs"]
mod tests;
