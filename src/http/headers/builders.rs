//! Profile-backed builders that materialize browser HTTP header collections.

use std::collections::HashMap;

use super::{BrowserHeaderMapError, HeaderPair, RequestHeaders};
use crate::fingerprint::{
    profile_facts, BrowserRequestKind, ProfileClientHintBrand, StealthProfile,
    ACCEPT_ENCODING_HEADER, ACCEPT_HEADER, ACCEPT_LANGUAGE_HEADER, DEFAULT_STEALTH_PROFILE,
    USER_AGENT_HEADER,
};
use crate::rotation::{named_or_rotated, profile_name};

pub(crate) fn is_identity_header(name: &str) -> bool {
    matches!(
        name,
        USER_AGENT_HEADER | ACCEPT_HEADER | ACCEPT_LANGUAGE_HEADER | ACCEPT_ENCODING_HEADER
    )
}

/// Resolve a named profile.
#[must_use]
pub fn get_profile(name: &str) -> Option<RequestHeaders> {
    crate::rotation::named_profile(name).map(browser_profile)
}

/// Deterministically rotate through browser HTTP profiles.
#[must_use]
pub fn rotate(index: usize) -> RequestHeaders {
    browser_profile(crate::rotation::profile_at(index))
}

/// Resolve an optional profile name, falling back to deterministic rotation.
#[must_use]
pub fn named_or_rotated_profile(name: Option<&str>, index: usize) -> RequestHeaders {
    browser_profile(named_or_rotated(name, index))
}

/// Materialize the HTTP profile for a canonical stealth profile.
#[must_use]
pub fn browser_profile(profile: StealthProfile) -> RequestHeaders {
    let facts = profile_facts(profile);
    RequestHeaders {
        name: profile_name(profile),
        fingerprint: profile,
        user_agent: facts.user_agent.to_string(),
        accept: facts.accept,
        accept_language: facts.accept_language.to_string(),
        accept_encoding: facts.accept_encoding,
    }
}

/// Ordered headers for `profile`.
#[must_use]
pub fn browser_headers(profile: StealthProfile) -> Vec<HeaderPair> {
    browser_profile(profile).headers()
}

/// Ordered headers for the fleet default browser profile.
#[must_use]
pub fn default_browser_headers() -> Vec<HeaderPair> {
    browser_headers(DEFAULT_STEALTH_PROFILE)
}

/// Ordered browser headers for transports that do not negotiate compressed bodies.
#[must_use]
pub fn browser_headers_without_compression(profile: StealthProfile) -> Vec<HeaderPair> {
    browser_profile(profile).headers_without_compression()
}

/// Ordered default browser headers for transports that do not negotiate compressed bodies.
#[must_use]
pub fn default_browser_headers_without_compression() -> Vec<HeaderPair> {
    browser_headers_without_compression(DEFAULT_STEALTH_PROFILE)
}

/// Ordered browser headers for a request surface.
#[must_use]
pub fn browser_request_headers(
    profile: StealthProfile,
    kind: BrowserRequestKind,
) -> Vec<HeaderPair> {
    browser_profile(profile).headers_for(kind)
}

/// Ordered default browser headers for a request surface.
#[must_use]
pub fn default_browser_request_headers(kind: BrowserRequestKind) -> Vec<HeaderPair> {
    browser_request_headers(DEFAULT_STEALTH_PROFILE, kind)
}

/// Ordered request-surface headers without compression negotiation.
#[must_use]
pub fn browser_request_headers_without_compression(
    profile: StealthProfile,
    kind: BrowserRequestKind,
) -> Vec<HeaderPair> {
    browser_profile(profile).headers_for_without_compression(kind)
}

/// Ordered default request-surface headers without compression negotiation.
#[must_use]
pub fn default_browser_request_headers_without_compression(
    kind: BrowserRequestKind,
) -> Vec<HeaderPair> {
    browser_request_headers_without_compression(DEFAULT_STEALTH_PROFILE, kind)
}

/// Build a typed HTTP header map for `profile`.
///
/// This is directly accepted by reqwest's `default_headers` because reqwest
/// re-exports the standard `http` header types.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical profile catalog contains
/// a value that cannot be represented as an HTTP header. Fix the profile
/// catalog; callers should fail closed instead of dropping identity headers.
pub fn browser_header_map(
    profile: StealthProfile,
) -> Result<::http::HeaderMap, BrowserHeaderMapError> {
    let mut headers = ::http::HeaderMap::new();
    apply_browser_header_map(&mut headers, profile)?;
    Ok(headers)
}

/// Build a typed HTTP header map for the fleet default browser profile.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical default profile contains
/// a value that cannot be represented as an HTTP header.
pub fn default_browser_header_map() -> Result<::http::HeaderMap, BrowserHeaderMapError> {
    browser_header_map(DEFAULT_STEALTH_PROFILE)
}

/// Build a typed HTTP header map for a browser request surface.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical profile catalog contains
/// a value that cannot be represented as an HTTP header.
pub fn browser_request_header_map(
    profile: StealthProfile,
    kind: BrowserRequestKind,
) -> Result<::http::HeaderMap, BrowserHeaderMapError> {
    let mut headers = ::http::HeaderMap::new();
    for header in browser_request_headers(profile, kind) {
        insert_http_header_if_absent(&mut headers, header)?;
    }
    Ok(headers)
}

/// Build a typed HTTP header map for the fleet default browser request surface.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical default profile contains
/// a value that cannot be represented as an HTTP header.
pub fn default_browser_request_header_map(
    kind: BrowserRequestKind,
) -> Result<::http::HeaderMap, BrowserHeaderMapError> {
    browser_request_header_map(DEFAULT_STEALTH_PROFILE, kind)
}

/// Build a typed HTTP header map for transports that cannot decode compressed bodies.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical profile catalog contains
/// a value that cannot be represented as an HTTP header.
pub fn browser_header_map_without_compression(
    profile: StealthProfile,
) -> Result<::http::HeaderMap, BrowserHeaderMapError> {
    let mut headers = ::http::HeaderMap::new();
    apply_browser_header_map_without_compression(&mut headers, profile)?;
    Ok(headers)
}

/// Build default browser headers for transports that cannot decode compressed bodies.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical default profile contains
/// a value that cannot be represented as an HTTP header.
pub fn default_browser_header_map_without_compression(
) -> Result<::http::HeaderMap, BrowserHeaderMapError> {
    browser_header_map_without_compression(DEFAULT_STEALTH_PROFILE)
}

/// Build a typed request-surface header map without compression negotiation.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical profile catalog contains
/// a value that cannot be represented as an HTTP header.
pub fn browser_request_header_map_without_compression(
    profile: StealthProfile,
    kind: BrowserRequestKind,
) -> Result<::http::HeaderMap, BrowserHeaderMapError> {
    let mut headers = ::http::HeaderMap::new();
    for header in browser_request_headers_without_compression(profile, kind) {
        insert_http_header_if_absent(&mut headers, header)?;
    }
    Ok(headers)
}

/// Build a typed default request-surface header map without compression.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical default profile contains
/// a value that cannot be represented as an HTTP header.
pub fn default_browser_request_header_map_without_compression(
    kind: BrowserRequestKind,
) -> Result<::http::HeaderMap, BrowserHeaderMapError> {
    browser_request_header_map_without_compression(DEFAULT_STEALTH_PROFILE, kind)
}

/// Insert browser headers into a typed HTTP header map without replacing
/// caller-supplied values.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical profile catalog contains
/// a value that cannot be represented as an HTTP header.
pub fn apply_browser_header_map(
    headers: &mut ::http::HeaderMap,
    profile: StealthProfile,
) -> Result<(), BrowserHeaderMapError> {
    for header in browser_headers(profile) {
        insert_http_header_if_absent(headers, header)?;
    }
    Ok(())
}

/// Insert browser headers except compression negotiation into a typed HTTP map
/// without replacing caller-supplied values.
///
/// Use this for transports that do not own transparent response decompression.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical profile catalog contains
/// a value that cannot be represented as an HTTP header.
pub fn apply_browser_header_map_without_compression(
    headers: &mut ::http::HeaderMap,
    profile: StealthProfile,
) -> Result<(), BrowserHeaderMapError> {
    for header in browser_headers_without_compression(profile) {
        insert_http_header_if_absent(headers, header)?;
    }
    Ok(())
}

/// Insert default browser headers into a typed HTTP header map without replacing caller values.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical default profile contains
/// a value that cannot be represented as an HTTP header.
pub fn apply_default_browser_header_map(
    headers: &mut ::http::HeaderMap,
) -> Result<(), BrowserHeaderMapError> {
    apply_browser_header_map(headers, DEFAULT_STEALTH_PROFILE)
}

/// Insert default browser headers except compression negotiation into a typed
/// HTTP map without replacing caller values.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the canonical default profile contains
/// a value that cannot be represented as an HTTP header.
pub fn apply_default_browser_header_map_without_compression(
    headers: &mut ::http::HeaderMap,
) -> Result<(), BrowserHeaderMapError> {
    apply_browser_header_map_without_compression(headers, DEFAULT_STEALTH_PROFILE)
}

/// Insert canonical browser headers into a string map without replacing
/// caller-supplied values.
pub fn apply_browser_headers(headers: &mut HashMap<String, String>, profile: StealthProfile) {
    for header in browser_headers(profile) {
        insert_if_absent_case_insensitive(headers, header.name, header.value);
    }
}

/// Insert default browser headers into a string map without replacing caller values.
pub fn apply_default_browser_headers(headers: &mut HashMap<String, String>) {
    apply_browser_headers(headers, DEFAULT_STEALTH_PROFILE);
}

fn insert_if_absent_case_insensitive(
    headers: &mut HashMap<String, String>,
    name: &'static str,
    value: String,
) {
    if headers
        .keys()
        .any(|existing| existing.eq_ignore_ascii_case(name))
    {
        return;
    }
    headers.insert(name.to_string(), value);
}

fn insert_http_header_if_absent(
    headers: &mut ::http::HeaderMap,
    header: HeaderPair,
) -> Result<(), BrowserHeaderMapError> {
    let name = ::http::header::HeaderName::from_bytes(header.name.as_bytes())
        .map_err(|_| BrowserHeaderMapError::InvalidName { name: header.name })?;
    if headers.contains_key(&name) {
        return Ok(());
    }

    let value = ::http::header::HeaderValue::from_str(&header.value).map_err(|_| {
        BrowserHeaderMapError::InvalidValue {
            name: header.name,
            value: header.value.clone(),
        }
    })?;
    headers.insert(name, value);
    Ok(())
}

pub(crate) fn sec_ch_ua_value(brands: &[ProfileClientHintBrand]) -> String {
    brands
        .iter()
        .map(|brand| format!("\"{}\";v=\"{}\"", brand.brand, brand.version))
        .collect::<Vec<_>>()
        .join(", ")
}
