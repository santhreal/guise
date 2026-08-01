//! Profile identity facts and header accessors.
//!
//! Thin wrappers over the `guise_profiles` catalogue exposing the
//! canonical User-Agent, navigation/browser/request headers, and
//! User-Agent inference for each [`StealthProfile`]. Pure data, no IO.

use super::*;

/// Canonical User-Agent for a stealth profile.
#[must_use]
pub const fn profile_user_agent(profile: StealthProfile) -> &'static str {
    profile_facts(profile).user_agent
}

/// Canonical identity facts for a stealth profile.
#[must_use]
pub const fn profile_facts(profile: StealthProfile) -> ProfileFacts {
    profile_catalog::profile_facts(profile)
}

/// Canonical identity facts for [`DEFAULT_STEALTH_PROFILE`].
#[must_use]
pub const fn default_profile_facts() -> ProfileFacts {
    profile_catalog::default_profile_facts()
}

/// Canonical User-Agent for [`DEFAULT_STEALTH_PROFILE`].
#[must_use]
pub const fn default_profile_user_agent() -> &'static str {
    profile_catalog::default_profile_user_agent()
}

/// Canonical profile-backed navigation headers for [`DEFAULT_STEALTH_PROFILE`].
#[must_use]
pub const fn default_profile_navigation_headers() -> [NavigationHeader; 3] {
    profile_catalog::default_profile_navigation_headers()
}

/// Canonical browser HTTP headers for [`DEFAULT_STEALTH_PROFILE`].
#[must_use]
pub const fn default_profile_browser_headers() -> [NavigationHeader; 4] {
    profile_catalog::default_profile_browser_headers()
}

/// Parse browser, platform, version, and stealth-profile facts from a User-Agent string.
#[must_use]
pub fn user_agent_facts(user_agent: &str) -> UserAgentFacts {
    profile_catalog::user_agent_facts(user_agent)
}

/// Infer the closest canonical stealth profile from a User-Agent string.
#[must_use]
pub fn infer_profile_from_user_agent(user_agent: &str) -> Option<StealthProfile> {
    profile_catalog::infer_profile_from_user_agent(user_agent)
}

/// Canonical profile-backed headers for browser-like top-level HTTP navigation.
///
/// Header names are lower-case for direct use with `http::HeaderName::from_static`.
#[must_use]
pub const fn profile_navigation_headers(profile: StealthProfile) -> [NavigationHeader; 3] {
    profile_catalog::profile_navigation_headers(profile)
}

/// Canonical browser HTTP headers including compression negotiation.
///
/// Header names are lower-case for direct use with `http::HeaderName::from_static`.
#[must_use]
pub const fn profile_browser_headers(profile: StealthProfile) -> [NavigationHeader; 4] {
    profile_catalog::profile_browser_headers(profile)
}

/// Canonical browser request headers for a request surface, including compression negotiation.
#[must_use]
pub const fn profile_request_headers(
    profile: StealthProfile,
    kind: BrowserRequestKind,
) -> BrowserRequestHeaders {
    profile_catalog::profile_request_headers(profile, kind)
}

/// Canonical browser request headers for [`DEFAULT_STEALTH_PROFILE`].
#[must_use]
pub const fn default_profile_request_headers(kind: BrowserRequestKind) -> BrowserRequestHeaders {
    profile_catalog::default_profile_request_headers(kind)
}

/// Canonical browser request headers for a request surface without `Accept-Encoding`.
#[must_use]
pub const fn profile_request_headers_without_compression(
    profile: StealthProfile,
    kind: BrowserRequestKind,
) -> BrowserRequestHeaders {
    profile_catalog::profile_request_headers_without_compression(profile, kind)
}

/// Canonical browser request headers without `Accept-Encoding` for [`DEFAULT_STEALTH_PROFILE`].
#[must_use]
pub const fn default_profile_request_headers_without_compression(
    kind: BrowserRequestKind,
) -> BrowserRequestHeaders {
    profile_catalog::default_profile_request_headers_without_compression(kind)
}
