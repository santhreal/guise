//! HTTP stealth profile helpers.
//!
//! `http-headers` exposes pure browser navigation headers plus TLS/HTTP2
//! catalogue metadata without pulling scanner or TLS dependencies. The `http`
//! feature additionally re-exports scanclient TLS profile types. The
//! wreq-backed [`StealthClient`] requires `tls-impersonate` on **both**
//! `stealth` and `scanclient` because it compiles BoringSSL.

#[cfg(feature = "http")]
pub use scanclient::tls_impersonate::{supported_profiles, ImpersonateProfile, ParseProfileError};

#[cfg(feature = "http-headers")]
#[path = "http/behavioral_noise.rs"]
pub mod behavioral_noise;

#[cfg(feature = "http-headers")]
#[path = "http/session_coherence.rs"]
pub mod session_coherence;

#[cfg(feature = "http-headers")]
#[path = "http/headers.rs"]
pub mod headers;

#[cfg(feature = "http-headers")]
#[path = "http/wire_emit.rs"]
pub mod wire_emit;

#[cfg(feature = "reqwest-client")]
#[path = "http/reqwest_client.rs"]
pub mod reqwest_client;

#[cfg(feature = "http-headers")]
pub use headers::{
    apply_browser_header_map, apply_browser_header_map_without_compression, apply_browser_headers,
    apply_default_browser_header_map, apply_default_browser_header_map_without_compression,
    apply_default_browser_headers, browser_header_map, browser_header_map_without_compression,
    browser_headers, browser_headers_without_compression, browser_profile,
    browser_request_header_map, browser_request_header_map_without_compression,
    browser_request_headers, browser_request_headers_without_compression,
    default_browser_header_map, default_browser_header_map_without_compression,
    default_browser_headers, default_browser_headers_without_compression,
    default_browser_request_header_map, default_browser_request_header_map_without_compression,
    default_browser_request_headers, default_browser_request_headers_without_compression,
    get_profile, named_or_rotated_profile, rotate, BrowserHeaderMapError, BrowserRequestKind,
    HeaderPair, RequestHeaders,
};

#[cfg(feature = "http-headers")]
pub use wire_emit::{
    capture_client_opening, encode_client_opening, encode_client_opening_for_profile,
    parse_client_akamai, WireEmitError, WireParseError, H2_CLIENT_PREFACE,
};

#[cfg(feature = "reqwest-client")]
pub use reqwest_client::{
    apply_browser_headers_to_reqwest_builder_without_compression,
    apply_default_browser_headers_to_reqwest_builder_without_compression,
    browser_client_builder_without_compression, default_browser_client_builder_without_compression,
};

#[cfg(feature = "tls-impersonate")]
pub use scanclient::tls_impersonate_stealth::{StealthClient, StealthError, StealthResponse};
