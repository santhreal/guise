//! Unit tests for [`super`], the persona coherence gate (`validate_overrides`),
//! the `ProfileBundle` constructors + their full-coherence guarantee, the brand
//! major-version checks, and (under `http`) the TLS-family arm.

use super::*;
use proptest::prelude::*;

#[test]
fn bundled_profiles_pass_full_coherence() {
    for bundle in [
        ProfileBundle::default_stealth(),
        ProfileBundle::chrome_131_macos(),
        ProfileBundle::chrome_131_windows(),
        ProfileBundle::firefox_133(),
        ProfileBundle::firefox_133_windows(),
        ProfileBundle::safari_17_5(),
        ProfileBundle::edge_131(),
    ] {
        bundle.validate_browser_coherence().unwrap();
        #[cfg(feature = "http")]
        bundle.validate_full_coherence().unwrap();
    }
}

#[test]
fn detect_incoherent_windows_platform() {
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    ov.platform = "MacIntel".into();
    assert!(validate_overrides(&ov).is_err());
}

#[test]
fn every_profile_http_accept_language_matches_js_navigator_languages() {
    // Cross-layer coherence (R056): the HTTP `Accept-Language` header (profile
    // facts) and the JS `navigator.languages` list (profile overrides) are
    // INDEPENDENT sources for the SAME logical fingerprint. If they drift, a
    // server reading Accept-Language and a script reading navigator.languages see
    // different language preferences, a heavily-weighted cross-layer tell. Every
    // shipped profile must keep the bare tag lists equal so a future non-English
    // persona (or an `accept_language` data slip) cannot silently ship the
    // mismatch. (Q-weights are dropped: `"en-US,en;q=0.9"` → `["en-US","en"]`.)
    for &profile in crate::fingerprint::ALL_PROFILES {
        let facts = crate::fingerprint::profile_facts(profile);
        let ov = profile_to_overrides(&profile);
        let header_tags: Vec<&str> = facts
            .accept_language
            .split(',')
            .map(|t| t.split(';').next().unwrap_or(t).trim())
            .filter(|t| !t.is_empty())
            .collect();
        let js_langs: Vec<&str> = ov.languages.iter().map(String::as_str).collect();
        assert_eq!(
            header_tags, js_langs,
            "{profile:?}: HTTP Accept-Language {:?} (tags {header_tags:?}) does not match \
             JS navigator.languages {js_langs:?}, cross-layer language tell",
            facts.accept_language
        );
    }
}

#[cfg(all(feature = "tier-b-toml", feature = "http"))]
#[test]
fn tier_b_toml_browser_aliases_use_shared_profile_catalog() {
    let path =
        std::env::temp_dir().join(format!("stealth-tier-b-alias-{}.toml", std::process::id()));
    std::fs::write(&path, "browser = \"chrome-win\"\ntls = \"chrome131\"\n")
        .expect("write tier-b alias fixture");

    let bundle = ProfileBundle::from_toml(&path).expect("shared alias should parse");
    assert_eq!(bundle.browser, StealthProfile::ChromeWindowsStable);
    assert_eq!(bundle.tls, ImpersonateProfile::Chrome131);

    let _ = std::fs::remove_file(path);
}

#[cfg(all(feature = "tier-b-toml", feature = "http"))]
#[test]
fn tier_b_toml_malformed_is_rejected_loud() {
    let path = std::env::temp_dir().join(format!("stealth-tier-b-bad-{}.toml", std::process::id()));
    std::fs::write(&path, "this is not valid toml :::::\n")
        .expect("write tier-b malformed fixture");

    let err = ProfileBundle::from_toml(&path).expect_err("malformed TOML must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("parse") || msg.contains("TOML"),
        "error should explain it is a parse failure: {msg}"
    );

    let _ = std::fs::remove_file(path);
}

#[cfg(all(feature = "tier-b-toml", feature = "http"))]
#[test]
fn tier_b_toml_incoherent_browser_tls_is_rejected_loud() {
    // Firefox UA paired with a Chrome TLS profile is the classic cross-layer tell.
    let path = std::env::temp_dir().join(format!(
        "stealth-tier-b-incoherent-{}.toml",
        std::process::id()
    ));
    std::fs::write(&path, "browser = \"firefox\"\ntls = \"chrome131\"\n")
        .expect("write tier-b incoherent fixture");

    let err = ProfileBundle::from_toml(&path).expect_err("incoherent TOML must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("incompatible") || msg.contains("coherent"),
        "error should explain the browser/TLS mismatch: {msg}"
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn default_stealth_bundle_uses_catalog_default_profile() {
    assert_eq!(
        ProfileBundle::default_stealth().browser,
        DEFAULT_STEALTH_PROFILE
    );
}

#[test]
fn every_rotation_persona_passes_full_coherence_at_build_time() {
    // G087/G093 exhaustive guard: the named-bundle test only covers 7 helpers;
    // every *rotation* persona must assemble into a fully coherent bundle
    // (browser + TLS). A future persona with a mismatched platform, brand
    // major, or TLS family trips here instead of leaking.
    for profile in crate::fingerprint::profiles::ROTATION_PROFILES {
        ProfileBundle::for_browser(*profile)
            .validate_full_coherence()
            .unwrap_or_else(|e| panic!("{profile:?} is incoherent: {e:?}"));
    }
}

#[cfg(feature = "http")]
#[test]
fn legacy_ie11_bundle_is_refused_at_build_time() {
    // G093: IE11 has no compatible TLS impersonation profile, so assembling a
    // bundle must fail rather than silently pair it with a Chrome ClientHello.
    let err = ProfileBundle::try_for_browser(StealthProfile::Ie11Windows)
        .expect_err("IE11 bundle must be refused");
    assert!(
        format!("{err}").contains("incompatible with TLS profile"),
        "expected TLS-family mismatch, got {err:?}"
    );
}

#[test]
fn detect_incoherent_brand_version() {
    // G087 adversarial twin: a Client-Hint brand whose major disagrees with
    // the UA's Chrome major is the "Sec-CH-UA says 999, UA says 13x" tell and
    // must be rejected. The positive path only proves coherent personas pass;
    // this proves the gate actually fires.
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    assert!(
        !ov.brands.is_empty(),
        "a Chrome persona must carry Client-Hint brands"
    );
    for entry in ov.brands.iter_mut() {
        entry.1 = "999".to_string();
    }
    match validate_overrides(&ov) {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("does not match UA major"),
            "expected a brand-major mismatch error, got: {msg}"
        ),
        other => panic!("expected Incoherent brand-major error, got {other:?}"),
    }
}

#[test]
fn detect_non_numeric_brand_version() {
    // Boundary twin: a non-numeric brand version is malformed Client-Hint data.
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    assert!(!ov.brands.is_empty());
    ov.brands[0].1 = "13a".to_string();
    match validate_overrides(&ov) {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("non-numeric version"),
            "expected a non-numeric-version error, got: {msg}"
        ),
        other => panic!("expected Incoherent non-numeric error, got {other:?}"),
    }
}

#[test]
fn detect_incoherent_macos_desktop_platform() {
    // A macOS-desktop Chrome UA paired with a non-MacIntel platform is the
    // mirror of the Windows tell (the gate must reject it, not just Windows).
    let mut ov = profile_to_overrides(&StealthProfile::ChromeMacStable);
    ov.platform = "Linux x86_64".into();
    match validate_overrides(&ov) {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("macOS desktop but platform is"),
            "expected a macOS-platform mismatch, got: {msg}"
        ),
        other => panic!("expected Incoherent macOS-platform error, got {other:?}"),
    }
}

#[test]
fn detect_incoherent_linux_desktop_platform() {
    // A desktop-Linux UA (X11; Linux) paired with a non-Linux platform is the
    // mirror of the Windows/macOS tells. FirefoxLinux is the primary shipped
    // persona, so this gap was directly load-bearing (the gate must reject it).
    let mut ov = profile_to_overrides(&StealthProfile::FirefoxLinux);
    assert!(
        ov.user_agent.contains("Linux") && !ov.user_agent.contains("Android"),
        "fixture must be a desktop-Linux persona"
    );
    ov.platform = "Win32".into();
    match validate_overrides(&ov) {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("Linux-based but platform is"),
            "expected a Linux-platform mismatch, got: {msg}"
        ),
        other => panic!("expected Incoherent Linux-platform error, got {other:?}"),
    }
}

#[test]
fn detect_incoherent_android_platform() {
    // Android UA with mobile=true but a non-Linux platform (Win32) passes the
    // mobile-flag rule, then must be caught by the Linux-platform rule, the
    // Android platform was previously ungated (only its mobile flag was).
    let mut ov = profile_to_overrides(&StealthProfile::ChromeAndroid);
    assert!(
        ov.user_agent.contains("Android") && ov.mobile,
        "fixture must be a mobile Android persona"
    );
    ov.platform = "Win32".into();
    match validate_overrides(&ov) {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("Linux-based but platform is"),
            "expected a Linux-platform mismatch, got: {msg}"
        ),
        other => panic!("expected Incoherent Android-platform error, got {other:?}"),
    }
}

#[test]
fn detect_incoherent_timezone_for_locale() {
    // R056: an operator who sets a timezone whose country contradicts the persona's
    // primary language is the "de-DE/Tokyo" tell at the Intl/Date layer. The shipped
    // en-US persona pinned to Europe/Berlin (DE) must be rejected.
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    assert!(
        ov.languages.first().is_some_and(|l| l.starts_with("en-US")),
        "fixture must be an en-US persona"
    );
    ov = ov.with_timezone("Europe/Berlin");
    match validate_overrides(&ov) {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("incoherent with primary language") && msg.contains("Europe/Berlin"),
            "expected a timezone-locale mismatch, got: {msg}"
        ),
        other => panic!("expected Incoherent timezone error, got {other:?}"),
    }
}

#[test]
fn coherent_alternate_timezone_in_the_same_country_passes() {
    // No false positive: an en-US persona may legitimately present ANY US timezone,
    // not only the derived default. America/Chicago is as coherent as New_York.
    let ov =
        profile_to_overrides(&StealthProfile::ChromeWindowsStable).with_timezone("America/Chicago");
    validate_overrides(&ov).expect("a same-country alternate timezone must stay coherent");
}

#[test]
fn uncatalogued_timezone_is_not_falsely_rejected() {
    // An exotic-but-valid zone the geo catalogue doesn't cover is not a KNOWN
    // incoherence, so the gate must not reject it (it can't prove a mismatch).
    let ov =
        profile_to_overrides(&StealthProfile::ChromeWindowsStable).with_timezone("Pacific/Chatham");
    validate_overrides(&ov).expect("an uncatalogued zone must not be rejected by the gate");
}

#[test]
fn android_personas_with_linux_arm_platform_are_coherent() {
    // Positive twin: the real Android personas ("Linux armv8l") must still pass.
    for profile in [
        StealthProfile::ChromeAndroid,
        StealthProfile::SamsungInternetAndroid,
    ] {
        let ov = profile_to_overrides(&profile);
        assert!(
            ov.platform.starts_with("Linux"),
            "{profile:?} should have a Linux-prefixed platform, got {}",
            ov.platform
        );
        validate_overrides(&ov)
            .unwrap_or_else(|e| panic!("{profile:?} must pass coherence, got: {e:?}"));
    }
}

#[test]
fn detect_apple_gpu_on_non_apple_platform() {
    // A Windows Chrome persona that claims an Apple GPU is a cross-surface tell
    // (WebGL vendor is heavily weighted). The gate must reject it.
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    assert_eq!(ov.platform, "Win32", "fixture must be a Windows persona");
    ov.webgl_vendor = "Apple Inc.".into();
    ov.webgl_renderer = "Apple GPU".into();
    match validate_overrides(&ov) {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("claims an Apple GPU") && msg.contains("but platform is"),
            "expected an Apple-GPU/platform mismatch, got: {msg}"
        ),
        other => panic!("expected Incoherent Apple-GPU error, got {other:?}"),
    }
}

#[test]
fn apple_gpu_personas_on_apple_platforms_are_coherent() {
    // Positive twin: the personas that legitimately carry an Apple GPU (Safari
    // on iPhone/iPad/Mac) must still pass, the rule must not false-positive on
    // the personas it protects.
    for profile in [
        StealthProfile::SafariIphone,
        StealthProfile::SafariIpad,
        StealthProfile::SafariMacStable,
    ] {
        let ov = profile_to_overrides(&profile);
        assert!(
            ov.webgl_vendor.contains("Apple") || ov.webgl_renderer.contains("Apple"),
            "{profile:?} should claim an Apple GPU"
        );
        validate_overrides(&ov)
            .unwrap_or_else(|e| panic!("{profile:?} must pass coherence, got: {e:?}"));
    }
}

#[test]
fn detect_incoherent_ios_platform() {
    // SafariIphone/SafariIpad ship, and an iOS UA is exempted from the macOS
    // MacIntel rule, so the gate must positively pin iOS to iPhone/iPad or an
    // iOS-UA-with-MacIntel-platform (the tempting wrong value) slips through.
    let mut ov = profile_to_overrides(&StealthProfile::SafariIphone);
    assert!(
        ov.user_agent.contains("iPhone"),
        "fixture must be an iPhone persona"
    );
    ov.platform = "MacIntel".into();
    match validate_overrides(&ov) {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("iOS UA (iPhone/iPad) but platform is"),
            "expected an iOS-platform mismatch, got: {msg}"
        ),
        other => panic!("expected Incoherent iOS-platform error, got {other:?}"),
    }
}

#[test]
fn ios_personas_with_apple_mobile_platform_are_coherent() {
    // Positive twin: SafariIphone ("iPhone") and SafariIpad ("iPad") must pass
    // the new rule must not false-positive on the personas it protects.
    for (profile, want) in [
        (StealthProfile::SafariIphone, "iPhone"),
        (StealthProfile::SafariIpad, "iPad"),
    ] {
        let ov = profile_to_overrides(&profile);
        assert_eq!(ov.platform, want, "{profile:?} platform");
        validate_overrides(&ov)
            .unwrap_or_else(|e| panic!("{profile:?} must pass coherence, got: {e:?}"));
    }
}

#[test]
fn linux_desktop_persona_with_linux_platform_is_coherent() {
    // Positive twin: the real FirefoxLinux/ChromeLinux personas (Linux UA +
    // "Linux x86_64" platform) must still PASS, the new rule must not
    // false-positive on the personas it exists to protect.
    for profile in [StealthProfile::FirefoxLinux, StealthProfile::ChromeLinux] {
        let ov = profile_to_overrides(&profile);
        assert!(
            ov.platform.starts_with("Linux"),
            "{profile:?} should have a Linux-prefixed platform"
        );
        validate_overrides(&ov)
            .unwrap_or_else(|e| panic!("{profile:?} must pass coherence, got: {e:?}"));
    }
}

#[test]
fn detect_android_ua_without_mobile_flag() {
    // An Android UA with userAgentData.mobile=false is incoherent, a real
    // Android Chrome always reports mobile=true.
    let mut ov = profile_to_overrides(&StealthProfile::ChromeAndroid);
    assert!(
        ov.user_agent.contains("Android"),
        "fixture must be an Android persona"
    );
    ov.mobile = false;
    match validate_overrides(&ov) {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("Android UA requires mobile=true"),
            "expected an Android mobile-flag error, got: {msg}"
        ),
        other => panic!("expected Incoherent Android error, got {other:?}"),
    }
}

#[test]
fn detect_chromium_ua_stripped_of_client_hint_brands() {
    // A Chromium UA with no userAgentData brands is the "Chrome that forgot its
    // Client Hints" tell (real Chrome always ships brands).
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    ov.brands.clear();
    match validate_overrides(&ov) {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("Chromium UA without userAgentData brands"),
            "expected a missing-brands error, got: {msg}"
        ),
        other => panic!("expected Incoherent missing-brands error, got {other:?}"),
    }
}

#[test]
fn detect_firefox_ua_leaking_client_hint_brands() {
    // The inverse client-hint tell (G032): a Firefox persona must NOT carry
    // userAgentData brands (only Chromium does. A FF UA + brands is incoherent).
    let mut ov = profile_to_overrides(&StealthProfile::FirefoxWindows);
    assert!(
        ov.brands.is_empty(),
        "a Firefox persona must not ship Client-Hint brands to begin with"
    );
    ov.brands.push(("Firefox".to_string(), "133".to_string()));
    match validate_overrides(&ov) {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("Firefox UA must not ship Client Hints brands"),
            "expected a Firefox-brands-leak error, got: {msg}"
        ),
        other => panic!("expected Incoherent Firefox-brands error, got {other:?}"),
    }
}

#[cfg(feature = "http")]
#[test]
fn detect_firefox_browser_paired_with_chrome_tls() {
    // G094, the classic cross-layer tell: a Firefox JS/UA identity bound to a
    // Chrome TLS ClientHello. `validate_full_coherence` must reject the bundle,
    // not just the predicate.
    let bundle = ProfileBundle {
        browser: StealthProfile::FirefoxLinux,
        tls: ImpersonateProfile::Chrome131,
    };
    match bundle.validate_full_coherence() {
        Err(ProfileError::Incoherent(msg)) => assert!(
            msg.contains("incompatible with TLS profile"),
            "expected a browser/TLS family mismatch, got: {msg}"
        ),
        other => panic!("expected Incoherent browser/TLS error, got {other:?}"),
    }
}

#[test]
fn seeded_bundle_is_deterministic() {
    // G088: the same seed must always produce the same persona.
    let a = ProfileBundle::from_seed(0x1234_5678_9abc_def0);
    let b = ProfileBundle::from_seed(0x1234_5678_9abc_def0);
    assert_eq!(a, b);
}

#[test]
fn seeded_bundles_cover_the_rotation_pool() {
    // G088 sanity: enough distinct seeds should exercise every rotation profile.
    use crate::fingerprint::profiles::ROTATION_PROFILES;
    let mut seen = Vec::new();
    for seed in 0..1024u64 {
        let browser = ProfileBundle::from_seed(seed).browser;
        if !seen.contains(&browser) {
            seen.push(browser);
        }
    }
    assert_eq!(
        seen.len(),
        ROTATION_PROFILES.len(),
        "seeded generator did not cover all rotation profiles"
    );
}

#[test]
fn every_seeded_bundle_passes_full_coherence() {
    // G089: the generator's contract is that ANY produced bundle is oracle-valid.
    for seed in [0u64, 1, 42, 12345, u64::MAX] {
        let bundle = ProfileBundle::from_seed(seed);
        bundle
            .validate_full_coherence()
            .unwrap_or_else(|e| panic!("seed {seed} produced incoherent bundle: {e:?}"));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_seeded_bundle_is_fully_coherent(seed: u64) {
        let bundle = ProfileBundle::from_seed(seed);
        bundle.validate_full_coherence().expect("seeded bundle must be coherent");
    }
}

#[cfg(all(feature = "tier-b-toml", feature = "http"))]
#[test]
fn tier_b_profile_toml_round_trips_through_bundle_to_overrides() {
    // G103: a Tier-B persona TOML must produce a bundle whose derived JS
    // surfaces match the TOML's intent. Load the shipped Chrome 131 / Windows
    // fixture and assert the bundle's overrides are coherent with a Windows
    // Chrome persona.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tier_b/profiles/chrome131_windows.toml");
    let bundle = ProfileBundle::from_toml(&path).expect("shipped chrome131_windows.toml must load");
    assert_eq!(bundle.browser, StealthProfile::ChromeWindowsStable);
    assert_eq!(bundle.tls, ImpersonateProfile::Chrome131);

    let ov = profile_to_overrides(&bundle.browser);
    assert!(
        ov.user_agent.contains("Windows NT 10.0"),
        "UA must claim Windows"
    );
    assert_eq!(ov.platform, "Win32", "platform must be Win32");
    assert!(
        !ov.brands.is_empty(),
        "Chrome persona must carry Client-Hint brands"
    );
    assert!(
        ov.brands
            .iter()
            .any(|(b, _)| b == "Chromium" || b == "Google Chrome"),
        "brands must include Chromium-family entry"
    );
    assert_eq!(ov.screen_width, 1920, "screen width must match persona");
    assert_eq!(ov.screen_height, 1080, "screen height must match persona");
    assert!(
        !ov.webgl_vendor.is_empty() && !ov.webgl_renderer.is_empty(),
        "ChromeWindowsStable must carry a WebGL GPU pair"
    );
}
