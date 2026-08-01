use super::*;

#[test]
fn safari_profile_constructs() {
    let profile = BehavioralProfile::safari_us();
    assert_eq!(profile.name, "safari_macos_us");
    assert!(!profile.emit_client_hints);
    assert!(profile.sec_ch_ua.is_none());
}

#[test]
fn android_profile_constructs() {
    let profile = BehavioralProfile::chrome_android();
    assert!(profile.emit_client_hints);
    assert!(profile.sec_ch_ua.is_none());
    assert!(!profile.user_agent_pool.is_empty());
    assert!(profile
        .user_agent_pool
        .iter()
        .any(|ua| ua.contains("Android")));
}

#[test]
fn all_profiles_have_non_empty_ua_pool() {
    for profile in [
        BehavioralProfile::chrome_us(),
        BehavioralProfile::firefox_eu(),
        BehavioralProfile::safari_us(),
        BehavioralProfile::chrome_android(),
    ] {
        assert!(
            !profile.user_agent_pool.is_empty(),
            "{} has empty UA pool",
            profile.name
        );
    }
}

#[test]
fn built_in_profiles_use_canonical_stealth_user_agents() {
    let cases = [
        (
            BehavioralProfile::chrome_us(),
            profile_user_agent(StealthProfile::ChromeWindowsStable),
        ),
        (
            BehavioralProfile::firefox_eu(),
            profile_user_agent(StealthProfile::FirefoxLinux),
        ),
        (
            BehavioralProfile::safari_us(),
            profile_user_agent(StealthProfile::SafariMacStable),
        ),
        (
            BehavioralProfile::chrome_android(),
            profile_user_agent(StealthProfile::ChromeAndroid),
        ),
    ];
    for (profile, user_agent) in cases {
        assert_eq!(
            profile.user_agent_pool,
            vec![user_agent],
            "{} must delegate UA selection to stealth",
            profile.name
        );
    }
}

#[test]
fn built_in_profiles_carry_typed_stealth_profiles() {
    let cases = [
        (
            BehavioralProfile::chrome_us(),
            StealthProfile::ChromeWindowsStable,
        ),
        (
            BehavioralProfile::firefox_eu(),
            StealthProfile::FirefoxLinux,
        ),
        (
            BehavioralProfile::safari_us(),
            StealthProfile::SafariMacStable,
        ),
        (
            BehavioralProfile::chrome_android(),
            StealthProfile::ChromeAndroid,
        ),
    ];

    for (profile, stealth_profile) in cases {
        assert_eq!(
            profile.stealth_profile,
            Some(stealth_profile),
            "{} must carry the shared profile that owns its browser surface",
            profile.name
        );
    }
}

#[test]
fn built_in_profiles_use_canonical_stealth_header_facts() {
    let cases = [
        (
            BehavioralProfile::chrome_us(),
            StealthProfile::ChromeWindowsStable,
        ),
        (
            BehavioralProfile::firefox_eu(),
            StealthProfile::FirefoxLinux,
        ),
        (
            BehavioralProfile::safari_us(),
            StealthProfile::SafariMacStable,
        ),
        (
            BehavioralProfile::chrome_android(),
            StealthProfile::ChromeAndroid,
        ),
    ];

    for (profile, stealth_profile) in cases {
        let facts = profile_facts(stealth_profile);
        let mut navigation_profile = profile.clone();
        navigation_profile.sec_fetch_mode = vec!["navigate"];
        let mut injector = NoiseInjector::new(navigation_profile, 42);
        let mut headers = Vec::new();
        injector.inject(&mut headers);

        assert_eq!(header_value(&headers, "accept"), Some(facts.accept));
        assert_eq!(
            header_value(&headers, "accept-encoding"),
            Some(facts.accept_encoding)
        );
    }
}

#[test]
fn built_in_chromium_client_hints_delegate_to_stealth() {
    let cases = [
        (
            BehavioralProfile::chrome_us(),
            StealthProfile::ChromeWindowsStable,
        ),
        (
            BehavioralProfile::chrome_android(),
            StealthProfile::ChromeAndroid,
        ),
    ];

    for (profile, stealth_profile) in cases {
        let mut injector = NoiseInjector::new(profile.clone(), 42);
        let mut headers = Vec::new();
        injector.inject(&mut headers);

        for name in ["Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform"] {
            let expected = canonical_header(stealth_profile, name);
            assert_eq!(
                header_value(&headers, name),
                Some(expected.as_str()),
                "{} {name} drifted from stealth",
                profile.name
            );
        }
    }
}

#[test]
fn android_client_hint_marks_mobile() {
    let mut injector = NoiseInjector::new(BehavioralProfile::chrome_android(), 42);
    let mut headers = Vec::new();
    injector.inject(&mut headers);
    assert_eq!(header_value(&headers, "sec-ch-ua-mobile"), Some("?1"));
}

#[test]
fn accept_language_weighted_sampling_is_stable() {
    let mut first_rng = StdRng::seed_from_u64(99);
    let mut second_rng = StdRng::seed_from_u64(99);
    let profile = BehavioralProfile::chrome_us();
    let variants = &profile.accept_language_variants;
    let first = sample_accept_language(variants, &mut first_rng);
    let second = sample_accept_language(variants, &mut second_rng);
    assert_eq!(first, second);
}

#[test]
fn accept_language_invalid_weights_use_default_fallback() {
    let mut rng = StdRng::seed_from_u64(101);
    let variants = &[
        ("invalid;q=1.0", 0.0),
        ("also-invalid;q=1.0", f64::NAN),
        ("negative-invalid;q=1.0", -1.0),
    ];

    assert_eq!(sample_accept_language(variants, &mut rng), "en-US,en;q=0.9");
}

#[test]
fn profile_name_is_accessible() {
    let injector = make_injector();
    assert_eq!(injector.profile_name(), "chrome_windows_us");
}
