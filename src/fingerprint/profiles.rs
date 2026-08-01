//! Named browser fingerprint profiles.
//!
//! [`crate::guise::apply_stealth`] hardens the *generic* signals
//! that betray a headless browser - `navigator.webdriver`, empty
//! plugins, missing `window.chrome`, etc. But once those obvious
//! tells are gone, the next layer of WAF fingerprinting reads
//! *coherent* values: the `User-Agent` header, `navigator.platform`,
//! `navigator.userAgentData.brands`, screen size, hardware
//! concurrency, GPU vendor/renderer, accept-language. A "Chrome on
//! Windows" UA paired with a `MacIntel` platform and a "Mesa Intel
//! Iris" GPU is *more* suspicious than vanilla headless, because
//! real browsers don't produce that combination.
//!
//! [`StealthProfile`] bundles a coherent set of those values per
//! (browser, OS, GPU class) tuple. Apply it with
//! [`super::browser::apply_stealth_profile`] (requires the `browser`
//! feature) in addition to generic CDP stealth passes.
//!
//! Only browsers/OSes that ship enough public fingerprint detail
//! to construct a coherent set are listed. Adding a new variant
//! here is cheap (one literal) but **NEVER** copy a UA string from
//! one variant into another - the WAF cross-checks UA against
//! `userAgentData.brands` and `platform`.
//!
//! This module is the canonical root: it owns the [`StealthProfile`]
//! and [`ProfileFacts`] catalogue re-exports, and splits its accessors
//! by responsibility into sibling modules - [`facts`] (identity facts
//! and header accessors), [`hints`] (User-Agent Client Hint
//! materialisation), and [`overrides`] (materialised overrides and the
//! CDP override JavaScript). Everything is re-exported here so existing
//! paths (`fingerprint::profiles::profile_facts`, etc.) keep resolving.
//!
//! # Example
//!
//! ```
//! use guise::fingerprint::{StealthProfile, profile_to_overrides};
//!
//! let p = StealthProfile::ChromeWindowsStable;
//! let ov = profile_to_overrides(&p);
//! assert!(ov.user_agent.contains("Windows NT"));
//! assert_eq!(ov.platform, "Win32");
//! assert!(ov.languages.contains(&"en-US".to_string()));
//! ```

use guise_profiles as profile_catalog;

pub use profile_catalog::{
    canonical_navigation_header_name, infer_initial_ttl, os_network_coherence,
    os_network_options_match, os_network_stack, profile_client_hint_brands,
    profile_client_hint_platform, profile_hardware, profile_hardware_at, profile_hardware_variants,
    profile_navigator_vendor, profile_os_network_stack, profile_platform, BrowserRequestHeaders,
    BrowserRequestKind, Ja4tError, NavigationHeader, NetworkOsCoherence, OsNetworkStack,
    ProfileClientHintBrand, ProfileFacts, ProfileHardware, StealthProfile, TcpWindow,
    UserAgentBrowser, UserAgentFacts, UserAgentPlatform, ACCEPT_ENCODING_HEADER, ACCEPT_HEADER,
    ACCEPT_LANGUAGE_HEADER, ALL_PROFILES, CHROME_WINDOWS_STABLE_USER_AGENT, CHROMIUM_IMAGE_ACCEPT,
    DEFAULT_STEALTH_PROFILE, FIREFOX_IMAGE_ACCEPT, FIREFOX_WINDOWS_STABLE_USER_AGENT,
    KNOWN_INITIAL_TTLS, ROTATION_PROFILES, SEC_FETCH_DEST_HEADER, SEC_FETCH_MODE_HEADER,
    SEC_FETCH_SITE_HEADER, SEC_FETCH_USER_HEADER, UPGRADE_INSECURE_REQUESTS_HEADER,
    USER_AGENT_HEADER,
};

mod facts;
mod hints;
mod intl_js;
mod overrides;

pub use facts::*;
pub use hints::*;
pub use intl_js::{default_timezone_for_locale, intl_spoof_js};
pub use overrides::*;

// `json_array` is a private serde helper that lives with the Client Hint
// types but is also used by `overrides::profile_js`. Re-export it within
// the crate so the sibling module sees it through the parent.
pub(crate) use hints::json_array;

#[cfg(test)]
mod tests;
