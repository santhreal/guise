//! Browser-shaped HTTP header templates derived from canonical profiles.

use std::fmt;

pub use crate::fingerprint::BrowserRequestKind;
use crate::fingerprint::{
    canonical_navigation_header_name, profile_client_hint_brands, profile_client_hint_platform,
    profile_facts, profile_request_headers, profile_request_headers_without_compression,
    StealthProfile,
};

// headers.rs is itself loaded via `#[path]` from http.rs, which changes where a
// bare `mod builders;` is searched (so point at the child file explicitly).
#[path = "headers/builders.rs"]
mod builders;

pub use builders::*;
pub(crate) use builders::{is_identity_header, sec_ch_ua_value};

/// One HTTP header in canonical browser order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderPair {
    /// Header name with browser-compatible casing.
    pub name: &'static str,
    /// Header value.
    pub value: String,
}

/// Error while materializing browser headers into an HTTP header map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserHeaderMapError {
    /// A canonical stealth header name is not valid for HTTP.
    InvalidName {
        /// Header name from the stealth profile catalog.
        name: &'static str,
    },
    /// A canonical stealth header value is not valid for HTTP.
    InvalidValue {
        /// Header name whose value failed validation.
        name: &'static str,
        /// Header value from the stealth profile catalog.
        value: String,
    },
}

impl fmt::Display for BrowserHeaderMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName { name } => write!(
                f,
                "invalid stealth browser header name `{name}`. Fix: repair the stealth browser profile catalog"
            ),
            Self::InvalidValue { name, value } => write!(
                f,
                "invalid stealth browser header value for `{name}` ({value:?}). Fix: repair the stealth browser profile catalog"
            ),
        }
    }
}

impl std::error::Error for BrowserHeaderMapError {}

/// Materialized browser HTTP profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeaders {
    /// Stable config name.
    pub name: &'static str,
    /// Canonical browser fingerprint profile.
    pub fingerprint: StealthProfile,
    /// User-Agent header value.
    pub user_agent: String,
    /// Accept header value.
    pub accept: &'static str,
    /// Accept-Language header value.
    pub accept_language: String,
    /// Accept-Encoding header value.
    pub accept_encoding: &'static str,
}

impl RequestHeaders {
    /// Build the ordered headers for this profile.
    #[must_use]
    pub fn headers(&self) -> Vec<HeaderPair> {
        self.headers_for(BrowserRequestKind::Navigation)
    }

    /// Build ordered headers for a specific browser request surface.
    #[must_use]
    pub fn headers_for(&self, kind: BrowserRequestKind) -> Vec<HeaderPair> {
        self.request_header_pairs(kind, true)
    }

    /// Build ordered browser headers for transports that cannot decode compressed bodies.
    ///
    /// Raw sockets and reqwest clients compiled without decompression support should not
    /// advertise `Accept-Encoding`; servers may otherwise return compressed bytes that the
    /// caller treats as plain text. The rest of the browser navigation envelope remains
    /// profile-backed and ordered.
    #[must_use]
    pub fn headers_without_compression(&self) -> Vec<HeaderPair> {
        self.headers_for_without_compression(BrowserRequestKind::Navigation)
    }

    /// Build ordered request-surface headers without compression negotiation.
    #[must_use]
    pub fn headers_for_without_compression(&self, kind: BrowserRequestKind) -> Vec<HeaderPair> {
        self.request_header_pairs(kind, false)
    }

    fn request_header_pairs(
        &self,
        kind: BrowserRequestKind,
        include_compression: bool,
    ) -> Vec<HeaderPair> {
        let catalog = if include_compression {
            profile_request_headers(self.fingerprint, kind)
        } else {
            profile_request_headers_without_compression(self.fingerprint, kind)
        };
        let mut hints = Some(self.client_hint_header_pairs());
        let mut headers = Vec::with_capacity(catalog.len() + hints.as_ref().map_or(0, Vec::len));

        for header in catalog.as_slice() {
            // Splice the client-hint block in front of the first non-identity
            // header. `take()` yields the hints exactly once, so subsequent
            // iterations see `None` and skip (no `expect` needed).
            if !is_identity_header(header.name) {
                if let Some(client_hints) = hints.take() {
                    headers.extend(client_hints);
                }
            }
            headers.push(HeaderPair {
                name: canonical_navigation_header_name(header.name),
                value: header.value.to_string(),
            });
        }
        if let Some(hints) = hints {
            headers.extend(hints);
        }
        headers
    }

    fn client_hint_header_pairs(&self) -> Vec<HeaderPair> {
        let brands = profile_client_hint_brands(self.fingerprint);
        let Some(platform) = profile_client_hint_platform(self.fingerprint) else {
            return Vec::new();
        };
        if brands.is_empty() {
            return Vec::new();
        }

        let facts = profile_facts(self.fingerprint);
        vec![
            HeaderPair {
                name: "Sec-CH-UA",
                value: sec_ch_ua_value(brands),
            },
            HeaderPair {
                name: "Sec-CH-UA-Mobile",
                value: if facts.mobile { "?1" } else { "?0" }.to_string(),
            },
            HeaderPair {
                name: "Sec-CH-UA-Platform",
                value: format!("\"{platform}\""),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::fingerprint::{profile_browser_headers, DEFAULT_STEALTH_PROFILE};

    use super::*;

    #[test]
    fn chrome_headers_derive_from_profile_catalog() {
        let profile = browser_profile(StealthProfile::ChromeWindowsStable);
        let facts = profile_facts(StealthProfile::ChromeWindowsStable);
        assert_eq!(profile.user_agent, facts.user_agent);

        let headers = profile.headers();
        assert_eq!(headers[0].name, "User-Agent");
        assert_eq!(headers[0].value, facts.user_agent);
        assert!(headers.iter().any(|h| h.name == "Sec-CH-UA"));
        assert!(headers
            .iter()
            .any(|h| h.name == "Sec-CH-UA-Platform" && h.value == "\"Windows\""));
    }

    #[test]
    fn browser_profile_base_headers_delegate_to_catalog_browser_headers() {
        let profile = browser_profile(StealthProfile::ChromeWindowsStable);
        let headers = profile.headers();
        let catalog_headers = profile_browser_headers(StealthProfile::ChromeWindowsStable);

        assert!(headers.len() > catalog_headers.len());
        for (actual, expected) in headers.iter().zip(catalog_headers) {
            assert_eq!(actual.name, canonical_navigation_header_name(expected.name));
            assert_eq!(actual.value, expected.value);
        }
    }

    #[test]
    fn firefox_omits_client_hints() {
        for profile in [StealthProfile::FirefoxLinux, StealthProfile::FirefoxWindows] {
            let headers = browser_headers(profile);
            assert!(headers.iter().all(|h| !h.name.starts_with("Sec-CH-UA")));
            assert!(
                headers
                    .iter()
                    .any(|h| h.name == "Accept-Language" && h.value == "en-US,en;q=0.9"),
                "{profile:?} should use Firefox accept-language weighting"
            );
        }
    }

    #[test]
    fn only_chromium_personas_emit_client_hints_exhaustively() {
        // G032/G108 exhaustive: Sec-CH-UA* is a Chromium-only signal. EVERY
        // shipped persona must emit client hints IFF its UA is a Chromium brand
        // a Firefox/Safari/IE persona leaking Sec-CH-UA, or a Chrome persona
        // omitting it, is a cross-layer tell. The 2-Firefox spot-check above is
        // widened here to the whole rotation set so a future persona wired wrong
        // fails CI instead of leaking.
        use crate::fingerprint::{
            profile_user_agent, user_agent_facts, UserAgentBrowser, ALL_PROFILES,
        };
        for profile in ALL_PROFILES {
            let browser = user_agent_facts(profile_user_agent(*profile)).browser;
            let is_chromium = matches!(
                browser,
                UserAgentBrowser::Chrome
                    | UserAgentBrowser::Edge
                    | UserAgentBrowser::Opera
                    | UserAgentBrowser::SamsungInternet
            );
            let emits_hints = browser_headers(*profile)
                .iter()
                .any(|h| h.name.starts_with("Sec-CH-UA"));
            assert_eq!(
                emits_hints, is_chromium,
                "{profile:?} ({browser:?}): client-hint emission must match Chromium-ness \
                 (Chromium → emits Sec-CH-UA, everything else → none)"
            );
        }
    }

    #[test]
    fn map_merge_preserves_existing_case_insensitively() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "custom".to_string());
        apply_browser_headers(&mut headers, StealthProfile::ChromeWindowsStable);
        assert_eq!(headers.get("user-agent"), Some(&"custom".to_string()));
        assert!(!headers.contains_key("User-Agent"));
        assert!(headers.contains_key("Accept"));
    }

    #[test]
    fn typed_header_map_contains_profile_navigation_headers() {
        let headers =
            browser_header_map(StealthProfile::ChromeWindowsStable).expect("profile headers");
        let facts = profile_facts(StealthProfile::ChromeWindowsStable);

        assert_eq!(
            headers.get("User-Agent").and_then(|v| v.to_str().ok()),
            Some(facts.user_agent)
        );
        assert_eq!(
            headers.get("Accept").and_then(|v| v.to_str().ok()),
            Some(facts.accept)
        );
        assert_eq!(
            headers.get("Accept-Language").and_then(|v| v.to_str().ok()),
            Some(facts.accept_language)
        );
        assert_eq!(
            headers.get("Sec-Fetch-Mode").and_then(|v| v.to_str().ok()),
            Some("navigate")
        );
    }

    #[test]
    fn audio_subresource_headers_shape_fetch_metadata_without_navigation_flags() {
        let headers = browser_request_header_map_without_compression(
            StealthProfile::ChromeWindowsStable,
            BrowserRequestKind::AudioSubresource,
        )
        .expect("profile headers");
        let facts = profile_facts(StealthProfile::ChromeWindowsStable);

        assert_eq!(
            headers.get("User-Agent").and_then(|v| v.to_str().ok()),
            Some(facts.user_agent)
        );
        assert_eq!(
            headers.get("Accept").and_then(|v| v.to_str().ok()),
            Some("*/*")
        );
        assert_eq!(
            headers.get("Accept-Language").and_then(|v| v.to_str().ok()),
            Some(facts.accept_language)
        );
        assert_eq!(
            headers.get("Sec-Fetch-Dest").and_then(|v| v.to_str().ok()),
            Some("audio")
        );
        assert_eq!(
            headers.get("Sec-Fetch-Mode").and_then(|v| v.to_str().ok()),
            Some("no-cors")
        );
        assert_eq!(
            headers.get("Sec-Fetch-Site").and_then(|v| v.to_str().ok()),
            Some("cross-site")
        );
        assert!(!headers.contains_key("Accept-Encoding"));
        assert!(!headers.contains_key("Upgrade-Insecure-Requests"));
        assert!(!headers.contains_key("Sec-Fetch-User"));
    }

    #[test]
    fn same_origin_fetch_headers_shape_xhr_metadata_without_navigation_flags() {
        let headers = browser_request_header_map_without_compression(
            StealthProfile::ChromeWindowsStable,
            BrowserRequestKind::SameOriginFetch,
        )
        .expect("profile headers");
        let facts = profile_facts(StealthProfile::ChromeWindowsStable);

        assert_eq!(
            headers.get("User-Agent").and_then(|v| v.to_str().ok()),
            Some(facts.user_agent)
        );
        assert_eq!(
            headers.get("Accept").and_then(|v| v.to_str().ok()),
            Some("*/*")
        );
        assert_eq!(
            headers.get("Accept-Language").and_then(|v| v.to_str().ok()),
            Some(facts.accept_language)
        );
        assert_eq!(
            headers.get("Sec-Fetch-Dest").and_then(|v| v.to_str().ok()),
            Some("empty")
        );
        assert_eq!(
            headers.get("Sec-Fetch-Mode").and_then(|v| v.to_str().ok()),
            Some("cors")
        );
        assert_eq!(
            headers.get("Sec-Fetch-Site").and_then(|v| v.to_str().ok()),
            Some("same-origin")
        );
        assert!(!headers.contains_key("Accept-Encoding"));
        assert!(!headers.contains_key("Upgrade-Insecure-Requests"));
        assert!(!headers.contains_key("Sec-Fetch-User"));
    }

    #[test]
    fn default_typed_header_map_matches_default_profile() {
        let default_headers = default_browser_header_map().expect("default headers");
        let explicit_headers =
            browser_header_map(DEFAULT_STEALTH_PROFILE).expect("explicit default headers");

        assert_eq!(default_headers, explicit_headers);
    }

    #[test]
    fn typed_header_map_merge_preserves_existing_values() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert("user-agent", ::http::HeaderValue::from_static("custom"));

        apply_browser_header_map(&mut headers, StealthProfile::ChromeWindowsStable)
            .expect("profile headers");

        assert_eq!(
            headers.get("User-Agent").and_then(|v| v.to_str().ok()),
            Some("custom")
        );
        assert!(headers.contains_key("Accept"));
    }

    #[test]
    fn typed_no_compression_header_map_merge_preserves_existing_values() {
        let mut headers = ::http::HeaderMap::new();
        headers.insert(
            "accept",
            ::http::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            "accept-encoding",
            ::http::HeaderValue::from_static("identity"),
        );

        apply_browser_header_map_without_compression(
            &mut headers,
            StealthProfile::ChromeWindowsStable,
        )
        .expect("profile headers");

        assert_eq!(
            headers.get("Accept").and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            headers.get("Accept-Encoding").and_then(|v| v.to_str().ok()),
            Some("identity")
        );
        assert!(headers.contains_key("User-Agent"));
        assert!(headers.contains_key("Accept-Language"));
        assert!(headers.contains_key("Sec-Fetch-Mode"));
    }

    #[test]
    fn no_compression_headers_keep_browser_navigation_metadata() {
        let headers = browser_headers_without_compression(StealthProfile::ChromeWindowsStable);

        assert!(headers.iter().any(|h| h.name == "User-Agent"));
        assert!(headers.iter().any(|h| h.name == "Accept"));
        assert!(headers.iter().any(|h| h.name == "Accept-Language"));
        assert!(headers.iter().any(|h| h.name == "Sec-Fetch-Mode"));
        assert!(headers.iter().all(|h| h.name != "Accept-Encoding"));
    }

    #[test]
    fn typed_header_map_without_compression_omits_accept_encoding() {
        let headers = browser_header_map_without_compression(StealthProfile::ChromeWindowsStable)
            .expect("profile headers");

        assert!(headers.contains_key("User-Agent"));
        assert!(headers.contains_key("Accept"));
        assert!(headers.contains_key("Accept-Language"));
        assert!(!headers.contains_key("Accept-Encoding"));
    }

    #[test]
    fn default_no_compression_map_matches_default_profile_without_compression() {
        let default_headers =
            default_browser_header_map_without_compression().expect("default headers");
        let explicit_headers = browser_header_map_without_compression(DEFAULT_STEALTH_PROFILE)
            .expect("explicit default headers");

        assert_eq!(default_headers, explicit_headers);
    }

    #[test]
    fn default_no_compression_apply_matches_default_profile_without_compression() {
        let mut headers = ::http::HeaderMap::new();
        apply_default_browser_header_map_without_compression(&mut headers)
            .expect("default profile headers");
        let explicit_headers = browser_header_map_without_compression(DEFAULT_STEALTH_PROFILE)
            .expect("explicit default headers");

        assert_eq!(headers, explicit_headers);
    }
}
