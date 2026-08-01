//! User-Agent Client Hint brand/platform materialisation.
//!
//! Converts a [`ProfileOverrides`] (or canonical [`StealthProfile`]) into
//! coherent low- and high-entropy `navigator.userAgentData` values:
//! brands, full version lists, platform, architecture, model. Chromium
//! only - Firefox/Safari profiles yield `None`.

use super::*;

/// One low- or high-entropy User-Agent Client Hint brand entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClientHintBrand {
    /// Browser brand token.
    pub brand: String,
    /// Major or full version string paired with the brand.
    pub version: String,
}

/// Coherent `navigator.userAgentData` values derived from a profile override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHints {
    /// Low-entropy `brands` value.
    pub brands: Vec<ClientHintBrand>,
    /// High-entropy `fullVersionList` value.
    pub full_version_list: Vec<ClientHintBrand>,
    /// Low-entropy `mobile` value.
    pub mobile: bool,
    /// Low-entropy `platform` value.
    pub platform: String,
    /// High-entropy `platformVersion` value.
    pub platform_version: String,
    /// High-entropy `architecture` value.
    pub architecture: String,
    /// High-entropy `bitness` value.
    pub bitness: String,
    /// High-entropy `model` value.
    pub model: String,
    /// High-entropy `uaFullVersion` value.
    pub ua_full_version: String,
    /// High-entropy `wow64` value.
    pub wow64: bool,
}

/// Materialise coherent User-Agent Client Hints for a Chromium-family override.
#[must_use]
pub fn client_hints_from_overrides(overrides: &ProfileOverrides) -> Option<ClientHints> {
    if overrides.brands.is_empty() {
        return None;
    }

    let brands = overrides
        .brands
        .iter()
        .map(|(brand, version)| ClientHintBrand {
            brand: brand.clone(),
            version: version.clone(),
        })
        .collect::<Vec<_>>();
    let full_version_list = overrides
        .brands
        .iter()
        .map(|(brand, version)| ClientHintBrand {
            brand: brand.clone(),
            version: full_version_for_brand(brand, version, &overrides.user_agent),
        })
        .collect::<Vec<_>>();
    // A real browser never sends an empty `Sec-CH-UA-Full-Version`. When the
    // brand list yields no non-GREASE version (all-GREASE filler or an empty
    // brand list), `.unwrap_or_default()` used to emit `""` — a fingerprint
    // tell, the exact inconsistency guise exists to prevent. Instead derive a
    // coherent full version from the UA's `Chrome/` token; if the UA is not
    // Chromium-family we cannot derive one, so fail closed (return `None`) and
    // let the caller reject the incoherent persona rather than ship an empty
    // header.
    let ua_full_version = match preferred_ua_full_version(&full_version_list) {
        Some(version) => version,
        None => ua_full_version_from_user_agent(&overrides.user_agent)?,
    };

    Some(ClientHints {
        brands,
        full_version_list,
        mobile: overrides.mobile,
        platform: client_hint_platform(&overrides.platform),
        platform_version: client_hint_platform_version(overrides),
        architecture: client_hint_architecture(&overrides.platform).to_string(),
        bitness: client_hint_bitness(&overrides.platform).to_string(),
        model: client_hint_model(overrides),
        ua_full_version,
        wow64: false,
    })
}

/// Materialise coherent User-Agent Client Hints for a canonical profile.
#[must_use]
pub fn profile_client_hints(profile: &StealthProfile) -> Option<ClientHints> {
    client_hints_from_overrides(&profile_to_overrides(profile))
}

/// JSON for the low-entropy `navigator.userAgentData.brands` value.
#[must_use]
pub fn client_hint_brands_json(overrides: &ProfileOverrides) -> String {
    client_hints_from_overrides(overrides)
        .map(|hints| json_array(&hints.brands))
        .unwrap_or_else(|| "[]".into())
}

/// JSON for the high-entropy `navigator.userAgentData.fullVersionList` value.
#[must_use]
pub fn client_hint_full_version_list_json(overrides: &ProfileOverrides) -> String {
    client_hints_from_overrides(overrides)
        .map(|hints| json_array(&hints.full_version_list))
        .unwrap_or_else(|| "[]".into())
}

#[allow(clippy::panic)] // crate-controlled persona data must always serialize (fail loud)
pub(crate) fn json_array<T: serde::Serialize>(value: &T) -> String {
    // Law 10 / G261: persona client-hint data is crate-controlled (brand lists,
    // version lists, language vecs, all `Vec<String>` / structs of strings), so
    // this serialize is infallible. If that invariant is ever broken, FAIL LOUDLY:
    // the prior `.unwrap_or_else(|_| "[]")` would silently ship an EMPTY
    // brand/version/language fingerprint (a real tell) while reporting success.
    serde_json::to_string(value).unwrap_or_else(|e| {
        panic!(
            "guise: serializing persona fingerprint JSON failed ({e}); persona \
             override data is crate-controlled and must always serialize"
        )
    })
}

fn client_hint_platform(platform: &str) -> String {
    if platform.starts_with("Win") {
        "Windows"
    } else if platform.starts_with("Mac") {
        "macOS"
    } else if platform.starts_with("iPhone") || platform.starts_with("iPad") {
        "iOS"
    } else if platform.starts_with("Linux arm") {
        "Android"
    } else if platform.starts_with("Linux") {
        "Linux"
    } else {
        "Unknown"
    }
    .to_string()
}

fn client_hint_platform_version(overrides: &ProfileOverrides) -> String {
    if overrides.platform.starts_with("Win") {
        "15.0.0".into()
    } else if overrides.platform.starts_with("Mac") {
        "14.0.0".into()
    } else if overrides.platform.starts_with("Linux arm") {
        android_version_from_ua(&overrides.user_agent).unwrap_or_else(|| "14.0.0".into())
    } else {
        String::new()
    }
}

fn client_hint_architecture(platform: &str) -> &'static str {
    if platform.starts_with("Linux arm") {
        "arm"
    } else {
        "x86"
    }
}

fn client_hint_bitness(platform: &str) -> &'static str {
    if platform.starts_with("Linux arm") {
        ""
    } else {
        "64"
    }
}

fn client_hint_model(overrides: &ProfileOverrides) -> String {
    if overrides.platform.starts_with("Linux arm") {
        android_model_from_ua(&overrides.user_agent).unwrap_or_default()
    } else {
        String::new()
    }
}

fn full_version_for_brand(brand: &str, major_version: &str, ua: &str) -> String {
    if major_version == "99" || brand.contains("Brand") {
        return "99.0.0.0".into();
    }

    let token = match brand {
        "Microsoft Edge" => "Edg/",
        "Opera" => "OPR/",
        "Samsung Internet" => "SamsungBrowser/",
        "Chromium" | "Google Chrome" | "Brave" => "Chrome/",
        _ => "",
    };
    if !token.is_empty() {
        if let Some(version) = version_after_token(ua, token) {
            return normalize_full_version(&version);
        }
    }

    normalize_full_version(major_version)
}

fn preferred_ua_full_version(full_version_list: &[ClientHintBrand]) -> Option<String> {
    for preferred in [
        "Google Chrome",
        "Microsoft Edge",
        "Brave",
        "Opera",
        "Samsung Internet",
        "Chromium",
    ] {
        if let Some(entry) = full_version_list
            .iter()
            .find(|entry| entry.brand == preferred && entry.version != "99.0.0.0")
        {
            return Some(entry.version.clone());
        }
    }

    full_version_list
        .iter()
        .find(|entry| entry.version != "99.0.0.0")
        .map(|entry| entry.version.clone())
}

/// Derive a coherent Chromium full version from the UA when the brand list
/// yields no non-GREASE version. Every Chromium-family UA carries a
/// `Chrome/<version>` token (Edge, Opera, Brave, Samsung all report it), so it
/// is the canonical source of the engine's full version. Returns `None` for a
/// non-Chromium UA so the caller fails closed instead of emitting an empty
/// `Sec-CH-UA-Full-Version` header (a fingerprint tell).
fn ua_full_version_from_user_agent(ua: &str) -> Option<String> {
    version_after_token(ua, "Chrome/").map(|version| normalize_full_version(&version))
}

fn version_after_token(ua: &str, token: &str) -> Option<String> {
    ua.split(token)
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .filter(|version| !version.is_empty())
        .map(ToString::to_string)
}

fn normalize_full_version(version: &str) -> String {
    let mut parts = version.split('.').collect::<Vec<_>>();
    while parts.len() < 4 {
        parts.push("0");
    }
    parts.truncate(4);
    parts.join(".")
}

fn android_version_from_ua(ua: &str) -> Option<String> {
    let version = ua
        .split("Android ")
        .nth(1)
        .and_then(|rest| rest.split([';', ')']).next())
        .map(str::trim)
        .filter(|version| !version.is_empty())?;
    Some(normalize_platform_version(version))
}

fn normalize_platform_version(version: &str) -> String {
    let mut parts = version.split('.').collect::<Vec<_>>();
    while parts.len() < 3 {
        parts.push("0");
    }
    parts.truncate(3);
    parts.join(".")
}

fn android_model_from_ua(ua: &str) -> Option<String> {
    let segment = ua
        .split('(')
        .nth(1)
        .and_then(|rest| rest.split(')').next())?;
    let mut parts = segment.split(';').map(str::trim);
    parts.find(|part| part.starts_with("Android "))?;
    parts
        .find(|part| !part.is_empty() && !part.starts_with("wv"))
        .map(ToString::to_string)
}
