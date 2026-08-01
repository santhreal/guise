//! Coherent browser fingerprint profile bundles (lifted from captchaforge).

mod profiles;

#[cfg(feature = "browser")]
pub mod browser;
#[cfg(feature = "browser")]
pub mod evasion;

pub mod bundle;
pub mod geo_coherence;
pub mod geo_region;
pub mod identity;
pub mod rarity;
pub mod surface;

// Header + TLS / JA3 fingerprint DATA (home-rule: fingerprint/ owns data; http/ applies it).
// Gated by `http-headers` (unchanged) so deps + feature semantics are preserved.
#[cfg(feature = "http-headers")]
pub mod akamai_h2;
pub mod audio_device_tier_b;
#[cfg(feature = "http-headers")]
pub mod browser_catalog;
#[cfg(feature = "http-headers")]
pub mod chrome_tls;
#[cfg(feature = "http-headers")]
pub mod cluster;
pub mod font_tier_b;
#[cfg(feature = "http-headers")]
pub mod ja3;
#[cfg(feature = "http-headers")]
pub mod ja4_family;
#[cfg(feature = "http-headers")]
pub(crate) mod ja4_hash;
#[cfg(feature = "tier-b-toml")]
pub mod os_network_tier_b;
pub mod screen_tier_b;
#[cfg(feature = "http-headers")]
pub mod tls_profiles;
#[cfg(feature = "http-headers")]
pub mod tls_targets;
#[cfg(feature = "tier-b-toml")]
pub mod voice_tier_b;
#[cfg(feature = "tier-b-toml")]
pub mod webgl_gpu_tier_b;

pub use bundle::{ProfileBundle, ProfileError};
#[cfg(feature = "browser")]
pub use evasion::{
    apply_fingerprint, collect_signals, evasion_js_source, FingerprintConfig, FingerprintSignals,
};
pub use geo_coherence::{
    identity_geo_coherence, persona_geo_self_probe, timezone_facts, EgressGeoMismatch,
    GeoCoherence, GeoIncoherence, GeoSelfProbe, ObservedEgressGeo, TimezoneFacts,
};
pub use geo_region::{geo_region_by_name, geo_region_by_timezone, GeoRegion, GEO_REGIONS};
#[cfg(feature = "tier-b-toml")]
pub use geo_region::{load_geo_region_directory, load_geo_region_from_toml, GeoRegionLoadError};
pub use identity::NavigatorProfile;
pub use profiles::{
    canonical_navigation_header_name, client_hint_brands_json, client_hint_full_version_list_json,
    client_hints_from_overrides, default_profile_browser_headers, default_profile_facts,
    default_profile_navigation_headers, default_profile_request_headers,
    default_profile_request_headers_without_compression, default_profile_user_agent,
    firefox_app_version, infer_initial_ttl, infer_profile_from_user_agent, os_network_coherence,
    os_network_options_match, os_network_stack, profile_browser_headers,
    profile_client_hint_brands, profile_client_hint_platform, profile_client_hints, profile_facts,
    profile_hardware, profile_hardware_at, profile_hardware_variants, profile_js,
    profile_navigation_headers, profile_os_network_stack, profile_platform,
    profile_request_headers, profile_request_headers_without_compression, profile_to_overrides,
    profile_to_overrides_at, profile_user_agent, user_agent_facts, BrowserRequestHeaders,
    BrowserRequestKind, ClientHintBrand, ClientHints, Ja4tError, NavigationHeader,
    NetworkOsCoherence, OsNetworkStack, ProfileClientHintBrand, ProfileFacts, ProfileHardware,
    ProfileOverrides, StealthProfile, TcpWindow, UserAgentBrowser, UserAgentFacts,
    UserAgentPlatform, ACCEPT_ENCODING_HEADER, ACCEPT_HEADER, ACCEPT_LANGUAGE_HEADER, ALL_PROFILES,
    CHROME_WINDOWS_STABLE_USER_AGENT, CHROMIUM_IMAGE_ACCEPT, DEFAULT_STEALTH_PROFILE,
    FIREFOX_IMAGE_ACCEPT, FIREFOX_WINDOWS_STABLE_USER_AGENT, KNOWN_INITIAL_TTLS, ROTATION_PROFILES,
    SEC_FETCH_DEST_HEADER, SEC_FETCH_MODE_HEADER, SEC_FETCH_SITE_HEADER, SEC_FETCH_USER_HEADER,
    UPGRADE_INSECURE_REQUESTS_HEADER, USER_AGENT_HEADER,
};
pub use surface::{Criticality, FingerprintSurface, SurfaceCategory};

// Shared native-camouflage prelude: defined with the profile override JS
// (always-compiled, in `profiles::overrides`) so both it and the browser-gated
// generic stealth script build their toString spoof from one source. Both
// consumers of THIS re-export (`browser::inject` and the browser-gated
// `evasion`) are browser-only, so the re-export carries the same gate, without
// it, a non-browser build sees an unused import.
#[cfg(feature = "browser")]
pub(crate) use profiles::NATIVE_SEAL_PRELUDE;
