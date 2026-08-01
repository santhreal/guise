//! reqwest client-builder integration for canonical browser HTTP identity.

use crate::fingerprint::{StealthProfile, DEFAULT_STEALTH_PROFILE};

use super::headers::{browser_header_map_without_compression, BrowserHeaderMapError};

/// Apply canonical browser navigation headers to an existing reqwest builder.
///
/// Compression negotiation is intentionally omitted. Use this for reqwest
/// clients that do not prove they own transparent decompression for every
/// advertised content coding.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the shared profile catalog contains an
/// invalid HTTP header name or value.
pub fn apply_browser_headers_to_reqwest_builder_without_compression(
    builder: reqwest::ClientBuilder,
    profile: StealthProfile,
) -> Result<reqwest::ClientBuilder, BrowserHeaderMapError> {
    Ok(builder.default_headers(browser_header_map_without_compression(profile)?))
}

/// Apply fleet-default browser navigation headers to an existing reqwest builder.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the shared default profile contains an
/// invalid HTTP header name or value.
pub fn apply_default_browser_headers_to_reqwest_builder_without_compression(
    builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder, BrowserHeaderMapError> {
    apply_browser_headers_to_reqwest_builder_without_compression(builder, DEFAULT_STEALTH_PROFILE)
}

/// Build a reqwest client builder with canonical browser navigation headers.
///
/// Compression negotiation is intentionally omitted. Callers can still add
/// timeout, redirect, proxy, cookie, and TLS policy before calling `build()`.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the shared profile catalog contains an
/// invalid HTTP header name or value.
pub fn browser_client_builder_without_compression(
    profile: StealthProfile,
) -> Result<reqwest::ClientBuilder, BrowserHeaderMapError> {
    apply_browser_headers_to_reqwest_builder_without_compression(
        reqwest::Client::builder(),
        profile,
    )
}

/// Build a reqwest client builder with the fleet-default browser navigation headers.
///
/// # Errors
///
/// Returns [`BrowserHeaderMapError`] if the shared default profile contains an
/// invalid HTTP header name or value.
pub fn default_browser_client_builder_without_compression(
) -> Result<reqwest::ClientBuilder, BrowserHeaderMapError> {
    browser_client_builder_without_compression(DEFAULT_STEALTH_PROFILE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::default_browser_header_map_without_compression;

    #[test]
    fn default_reqwest_builder_uses_the_valid_shared_header_catalog() {
        let headers =
            default_browser_header_map_without_compression().expect("shared headers are valid");
        let facts = crate::fingerprint::default_profile_facts();

        assert_eq!(
            headers
                .get(reqwest::header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            Some(facts.user_agent)
        );
        assert!(
            !headers.contains_key(reqwest::header::ACCEPT_ENCODING),
            "reqwest helper must not advertise compression for generic callers"
        );

        let _builder = default_browser_client_builder_without_compression()
            .expect("reqwest builder should accept shared headers");
    }

    #[test]
    fn chrome_reqwest_builder_contains_chrome_ua() {
        // Assert the UA the shared catalog pins for this persona, the header map
        // is exactly what feeds the builder. The previous version built a client
        // and discarded it (`let _ = client`) WITHOUT ever checking the UA its
        // name promised: Law 6 decoration (passed on any non-error build).
        let headers = browser_header_map_without_compression(StealthProfile::ChromeWindowsStable)
            .expect("chrome header map is valid");
        let ua = headers
            .get(reqwest::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .expect("chrome header map carries a User-Agent");
        assert!(
            ua.contains("Chrome"),
            "Chrome persona UA must name the Chrome engine: {ua:?}"
        );
        assert!(
            ua.contains("Windows"),
            "ChromeWindowsStable UA must name the Windows platform: {ua:?}"
        );
        assert!(
            !ua.contains("Firefox"),
            "Chrome persona UA must not leak the Firefox token: {ua:?}"
        );

        // And the builder still accepts those headers without erroring.
        browser_client_builder_without_compression(StealthProfile::ChromeWindowsStable)
            .expect("chrome builder")
            .build()
            .expect("chrome client build");
    }

    #[test]
    fn firefox_reqwest_builder_contains_firefox_ua() {
        let headers = browser_header_map_without_compression(StealthProfile::FirefoxLinux)
            .expect("firefox header map is valid");
        let ua = headers
            .get(reqwest::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .expect("firefox header map carries a User-Agent");
        assert!(
            ua.contains("Firefox"),
            "Firefox persona UA must name the Firefox engine: {ua:?}"
        );
        assert!(
            ua.contains("Linux"),
            "FirefoxLinux UA must name the Linux platform: {ua:?}"
        );
        assert!(
            !ua.contains("Chrome"),
            "Firefox persona UA must not leak the Chrome token: {ua:?}"
        );

        browser_client_builder_without_compression(StealthProfile::FirefoxLinux)
            .expect("firefox builder")
            .build()
            .expect("firefox client build");
    }

    #[test]
    fn apply_browser_headers_to_existing_builder_does_not_panic() {
        let builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
        let builder = apply_browser_headers_to_reqwest_builder_without_compression(
            builder,
            StealthProfile::SafariMacStable,
        )
        .expect("apply headers");
        let _client = builder.build().expect("build client");
    }

    #[test]
    fn apply_default_browser_headers_to_existing_builder_does_not_panic() {
        let builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
        let builder = apply_default_browser_headers_to_reqwest_builder_without_compression(builder)
            .expect("apply default headers");
        let _client = builder.build().expect("build client");
    }
}
