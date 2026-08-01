//! Cross-profile consistency tests (MASTER_PLAN 02 test type 4).
//!
//! G258/G259: feature-gated via `required-features = ["fingerprint", "rotation"]`
//! in Cargo.toml, so single-feature builds skip this target instead of failing on
//! absent modules. The `every_rotation_profile_has_coherent_default_tls` test
//! additionally carries an inner `#[cfg(feature = "http")]` for the TLS layer.

use guise::fingerprint::bundle::validate_overrides;
use guise::fingerprint::{profile_facts, profile_to_overrides, ProfileBundle, StealthProfile};
use guise::http::headers::browser_profile;
use guise::rotation::{all_profiles, profiles};

#[test]
fn every_stealth_profile_materialises_coherent_overrides() {
    // Every shipped profile must materialise to coherent browser-side overrides.
    // Legacy personas (e.g. IE11) have no compatible TLS profile, so this test
    // checks the override layer directly rather than forcing bundle assembly.
    for browser in all_profiles() {
        let browser = *browser;
        let overrides = profile_to_overrides(&browser);
        validate_overrides(&overrides).unwrap_or_else(|e| panic!("{browser:?}: {e}"));
    }
}

#[test]
fn every_rotation_profile_assembles_into_a_coherent_bundle() {
    // G093 positive path: every rotation persona (which has a matching TLS
    // profile) must assemble through the bundle constructor successfully.
    for browser in profiles() {
        let browser = *browser;
        let bundle = ProfileBundle::for_browser(browser);
        bundle
            .validate_browser_coherence()
            .unwrap_or_else(|e| panic!("{browser:?}: {e}"));
    }
}

#[cfg(feature = "http")]
#[test]
fn every_rotation_profile_has_coherent_default_tls() {
    for browser in profiles() {
        let browser = *browser;
        let bundle = ProfileBundle::for_browser(browser);
        bundle
            .validate_full_coherence()
            .unwrap_or_else(|e| panic!("{browser:?} tls: {e}"));
    }
}

#[test]
fn tier_b_constructors_match_phase_doc() {
    let mac = ProfileBundle::chrome_131_macos();
    assert_eq!(mac.browser, StealthProfile::ChromeMacStable);
    let win = ProfileBundle::chrome_131_windows();
    assert_eq!(win.browser, StealthProfile::ChromeWindowsStable);
    let _ = ProfileBundle::firefox_133();
    let firefox_win = ProfileBundle::firefox_133_windows();
    assert_eq!(firefox_win.browser, StealthProfile::FirefoxWindows);
    let _ = ProfileBundle::safari_17_5();
    let _ = ProfileBundle::edge_131();
}

#[cfg(feature = "http")]
#[test]
fn persona_seed_flows_unmodified_through_bundle_headers_and_tls() {
    // G122/G123: the same persona seed must reach the browser identity layer,
    // the HTTP header layer, and the TLS layer without any layer silently
    // dropping or altering it. This test is the cross-layer trace.
    for browser in profiles() {
        let browser = *browser;
        let facts = profile_facts(browser);
        let bundle = ProfileBundle::for_browser(browser);

        // Bundle must assemble a TLS profile that matches the browser family.
        bundle
            .validate_full_coherence()
            .unwrap_or_else(|e| panic!("{browser:?}: bundle/TLS mismatch: {e}"));

        // HTTP header layer must carry the same identity facts as the bundle.
        let headers = browser_profile(browser);
        assert_eq!(
            headers.user_agent, facts.user_agent,
            "{browser:?}: HTTP User-Agent diverged from persona facts"
        );
        assert_eq!(
            headers.accept, facts.accept,
            "{browser:?}: HTTP Accept diverged from persona facts"
        );
        assert_eq!(
            headers.accept_language, facts.accept_language,
            "{browser:?}: HTTP Accept-Language diverged from persona facts"
        );
        assert_eq!(
            headers.accept_encoding, facts.accept_encoding,
            "{browser:?}: HTTP Accept-Encoding diverged from persona facts"
        );
    }
}
