//! Probe classifiers: map a probed JSON value to a `ProbeOutcome`.

use super::ProbeOutcome;
use crate::fingerprint::user_agent_facts;

pub(super) fn classify_must_be_undefined(v: &serde_json::Value) -> ProbeOutcome {
    if matches!(v, serde_json::Value::Null) {
        ProbeOutcome::Pass
    } else {
        ProbeOutcome::Critical(format!("expected undefined / null, got {v}"))
    }
}

/// `navigator.webdriver` is genuine on a real browser: the property is PRESENT
/// with value `false` (it only becomes `true` under automation). Hiding it to
/// `undefined`/`null` is itself a tell, a real, un-automated browser reports
/// `false`. So `false` (and, leniently, `null`) pass; `true` is the
/// automation-revealing Critical.
pub(super) fn classify_webdriver_ok(v: &serde_json::Value) -> ProbeOutcome {
    match v {
        serde_json::Value::Bool(false) | serde_json::Value::Null => ProbeOutcome::Pass,
        serde_json::Value::Bool(true) => {
            ProbeOutcome::Critical("navigator.webdriver === true, automation leak".to_string())
        }
        other => ProbeOutcome::Drift(format!("expected false, got {other}")),
    }
}

pub(super) fn classify_must_be_true(v: &serde_json::Value) -> ProbeOutcome {
    if v.as_bool() == Some(true) {
        ProbeOutcome::Pass
    } else {
        ProbeOutcome::Critical(format!("expected true, got {v}"))
    }
}

pub(super) fn classify_must_be_nonzero_int(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_u64().or(v.as_i64().map(|i| i as u64)) {
        Some(n) if n > 0 => ProbeOutcome::Pass,
        Some(0) => ProbeOutcome::Critical("expected nonzero count, got 0".to_string()),
        _ => ProbeOutcome::Drift(format!("expected integer, got {v}")),
    }
}

pub(super) fn classify_must_be_nonempty_string(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_str() {
        Some(s) if !s.is_empty() => ProbeOutcome::Pass,
        Some(_) => ProbeOutcome::Critical("expected nonempty string, got empty".to_string()),
        _ => ProbeOutcome::Drift(format!("expected string, got {v}")),
    }
}

pub(super) fn classify_must_be_empty_string(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_str() {
        Some("") => ProbeOutcome::Pass,
        Some(s) => {
            ProbeOutcome::Critical(format!("expected empty string (Firefox vendor), got {s:?}"))
        }
        _ => ProbeOutcome::Drift(format!("expected string, got {v}")),
    }
}

pub(super) fn classify_must_be_firefox_ua(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_str() {
        Some(ua) => {
            let facts = user_agent_facts(ua);
            if facts.headless {
                ProbeOutcome::Critical(format!("UA leaks a headless token: {ua}"))
            } else if matches!(facts.browser, crate::fingerprint::UserAgentBrowser::Firefox)
                && ua.contains("Gecko/")
            {
                ProbeOutcome::Pass
            } else {
                ProbeOutcome::Critical(format!("expected a Gecko/Firefox UA, got {ua}"))
            }
        }
        None => ProbeOutcome::Drift(format!("UA not a string: {v}")),
    }
}

pub(super) fn classify_must_be_chromium_ua(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_str() {
        Some(ua) => {
            let facts = user_agent_facts(ua);
            if facts.headless {
                ProbeOutcome::Critical(format!("UA leaks HeadlessChrome: {ua}"))
            } else if facts.chromium_major_version.is_some() {
                ProbeOutcome::Pass
            } else {
                ProbeOutcome::Drift(format!("non-Chromium UA: {ua}"))
            }
        }
        None => ProbeOutcome::Drift(format!("UA not a string: {v}")),
    }
}

pub(super) fn classify_must_not_contain_swiftshader(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_str() {
        Some(s) if s.to_lowercase().contains("swiftshader") => {
            ProbeOutcome::Critical(format!("renderer leaks SwiftShader: {s}"))
        }
        Some(s) if !s.is_empty() => ProbeOutcome::Pass,
        _ => ProbeOutcome::Drift(format!("expected non-empty renderer, got {v}")),
    }
}

/// A resolved IANA time-zone id is either `UTC` or `Area/Location`
/// (e.g. `America/Phoenix`, `Etc/GMT+5`, `America/Argentina/Buenos_Aires`).
/// Allowed characters are ASCII letters, digits, `_`, `+`, `-`, and `/`. A
/// genuine consumer browser always resolves one; an empty value betrays a
/// stripped-ICU / headless build.
pub(super) fn is_iana_timezone(s: &str) -> bool {
    if s == "UTC" {
        return true;
    }
    if !s.contains('/') || s.starts_with('/') || s.ends_with('/') || s.contains("//") {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-' | '/'))
}

/// Classify `Intl.DateTimeFormat().resolvedOptions().timeZone`. We assert the
/// resolved zone is a well-formed IANA id. NOT a specific zone (the persona
/// carries no timezone field, so pinning one would overclaim). An EMPTY zone is
/// the tell a stripped/headless environment exposes.
pub(super) fn classify_iana_timezone(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_str() {
        Some(s) if is_iana_timezone(s) => ProbeOutcome::Pass,
        Some("") => ProbeOutcome::Critical(
            "Intl resolved an EMPTY time zone, a stripped-ICU / headless tell".to_string(),
        ),
        Some(s) => ProbeOutcome::Drift(format!("resolved time zone is not IANA-shaped: {s:?}")),
        None => ProbeOutcome::Drift(format!("time zone not a string: {v}")),
    }
}

pub(super) fn classify_must_be_at_least_4_int(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_u64() {
        Some(n) if n >= 4 => ProbeOutcome::Pass,
        Some(n) => ProbeOutcome::Drift(format!("expected >=4, got {n}")),
        _ => ProbeOutcome::Drift(format!("not an integer: {v}")),
    }
}

pub(super) fn classify_in_range(v: &serde_json::Value, min: u64, max: u64) -> ProbeOutcome {
    match v.as_u64() {
        Some(n) if (min..=max).contains(&n) => ProbeOutcome::Pass,
        Some(n) => ProbeOutcome::Drift(format!("expected [{min}, {max}], got {n}")),
        _ => ProbeOutcome::Drift(format!("not an integer: {v}")),
    }
}

pub(super) fn classify_hardware_concurrency(v: &serde_json::Value) -> ProbeOutcome {
    classify_in_range(v, 2, 16)
}
pub(super) fn classify_device_memory(v: &serde_json::Value) -> ProbeOutcome {
    classify_in_range(v, 1, 64)
}
pub(super) fn classify_color_depth(v: &serde_json::Value) -> ProbeOutcome {
    classify_in_range(v, 24, 30)
}
pub(super) fn classify_screen_size(v: &serde_json::Value) -> ProbeOutcome {
    classify_in_range(v, 390, 5120)
}
pub(super) fn classify_dpr(v: &serde_json::Value) -> ProbeOutcome {
    classify_in_range(v, 1, 5)
}
pub(super) fn classify_history(v: &serde_json::Value) -> ProbeOutcome {
    classify_in_range(v, 1, 100)
}

/// Canvas/audio farbling must be SESSION-STABLE, not per-read random. A real
/// browser returns DETERMINISTIC canvas/audio across reads within a page, and so
/// must a correct farble: guise keys its perturbation on absolute pixel
/// coordinates / sample index plus a per-session seed, so two reads are
/// byte-identical. Per-READ variation is itself a strong tamper tell, a script
/// that reads a canvas twice and sees different pixels KNOWS it is being farbled,
/// and fingerprinters (CreepJS) flag an "unstable" canvas.
///
/// The probe returns `true` when two reads DIFFER (unstable). So the honest,
/// browser-truth mapping is the inverse of "is something randomizing per read":
///   * `false` (stable) → **Pass**: real-browser-coherent, no instability tell.
///     Both a native surface and a correct deterministic farble land here. Whether
///     the farble actually DEVIATES from the host fingerprint is a cross-session
///     property this single-session probe cannot see; it is verified in AGGREGATE
///     by the live oracle (CreepJS / the differential gate), per `NoiseSpoofLink`.
///   * `true` (unstable) → **Drift**: the per-read-variation tell a naive
///     randomizer would trip; surfaced so it is caught, never shipped as a defense.
pub(super) fn classify_session_noise(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_bool() {
        Some(false) => ProbeOutcome::Pass,
        Some(true) => ProbeOutcome::Drift(
            "surface differs between two reads in one session, a per-read instability \
             tell; deterministic, session-stable farbling must not vary per read"
                .to_string(),
        ),
        _ => ProbeOutcome::Drift(format!("expected boolean, got {v}")),
    }
}

pub(super) fn classify_must_be_native_code(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_str() {
        Some(s) if s.contains("[native code]") => ProbeOutcome::Pass,
        Some(s) => ProbeOutcome::Critical(format!("toString leaks wrapper source: {s}")),
        _ => ProbeOutcome::Drift(format!("not a string: {v}")),
    }
}

/// Firefox does not expose `navigator.userAgentData` / Client Hints. A real
/// Gecko browser returns `undefined`, so the probe evaluates to `null`. If the
/// property exists, its `brands` / `fullVersionList` arrays MUST be empty, any
/// non-empty list is a Chromium-impersonation tell.
pub(super) fn classify_user_agent_data_empty_or_absent(v: &serde_json::Value) -> ProbeOutcome {
    match v {
        serde_json::Value::Null => ProbeOutcome::Pass,
        serde_json::Value::Array(a) if a.is_empty() => ProbeOutcome::Pass,
        serde_json::Value::Array(a) => ProbeOutcome::Critical(format!(
            "Firefox persona exposed non-empty Client Hints brands: {a:?}"
        )),
        other => ProbeOutcome::Drift(format!("unexpected userAgentData shape: {other}")),
    }
}

// Array-length helpers (dead-code-tolerated until referenced).
#[allow(dead_code)]
pub(super) fn classify_array_at_least_2(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_array() {
        Some(arr) if arr.len() >= 2 => ProbeOutcome::Pass,
        Some(arr) => ProbeOutcome::Critical(format!("array length {} < 2", arr.len())),
        _ => ProbeOutcome::Drift(format!("not an array: {v}")),
    }
}

#[allow(dead_code)]
pub(super) fn classify_array_at_least_4(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_array() {
        Some(arr) if arr.len() >= 4 => ProbeOutcome::Pass,
        Some(arr) => ProbeOutcome::Critical(format!("array length {} < 4", arr.len())),
        _ => ProbeOutcome::Drift(format!("not an array: {v}")),
    }
}
