use super::*;

#[test]
fn inject_adds_user_agent() {
    let mut injector = make_injector();
    let mut headers: Vec<(String, String)> = Vec::new();
    injector.inject(&mut headers);
    assert!(
        headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("user-agent")),
        "user-agent must be injected"
    );
}

#[test]
fn inject_adds_accept_language() {
    let mut injector = make_injector();
    let mut headers = Vec::new();
    injector.inject(&mut headers);
    assert!(headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("accept-language")));
}

#[test]
fn inject_adds_accept_encoding() {
    let mut injector = make_injector();
    let mut headers = Vec::new();
    injector.inject(&mut headers);
    assert!(headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("accept-encoding")));
}

#[test]
fn inject_adds_sec_fetch_mode() {
    let mut injector = make_injector();
    let mut headers = Vec::new();
    injector.inject(&mut headers);
    assert!(headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("sec-fetch-mode")));
}

#[test]
fn inject_navigation_surface_delegates_to_catalog() {
    let mut injector = NoiseInjector::new(single_mode_profile("navigate"), 1);
    let mut headers = Vec::new();
    injector.inject(&mut headers);

    assert_eq!(
        header_value(&headers, "accept"),
        Some(profile_facts(StealthProfile::ChromeWindowsStable).accept)
    );
    assert_eq!(header_value(&headers, "sec-fetch-dest"), Some("document"));
    assert_eq!(header_value(&headers, "sec-fetch-mode"), Some("navigate"));
    assert_eq!(header_value(&headers, "sec-fetch-site"), Some("none"));
    assert_eq!(header_value(&headers, "sec-fetch-user"), Some("?1"));
    assert_eq!(
        header_value(&headers, "upgrade-insecure-requests"),
        Some("1")
    );
}

#[test]
fn inject_no_cors_surface_uses_catalog_image_shape() {
    let mut injector = NoiseInjector::new(single_mode_profile("no-cors"), 1);
    let mut headers = Vec::new();
    injector.inject(&mut headers);

    // Background image noise carries the real Chromium <img> Accept, not a bare
    // */* (the noise must look like genuine browser traffic (G039/G040)).
    assert_eq!(
        header_value(&headers, "accept"),
        Some(crate::fingerprint::CHROMIUM_IMAGE_ACCEPT)
    );
    assert_eq!(header_value(&headers, "sec-fetch-dest"), Some("image"));
    assert_eq!(header_value(&headers, "sec-fetch-mode"), Some("no-cors"));
    assert_eq!(header_value(&headers, "sec-fetch-site"), Some("cross-site"));
    assert_eq!(header_value(&headers, "sec-fetch-user"), None);
    assert_eq!(header_value(&headers, "upgrade-insecure-requests"), None);
}

#[test]
fn inject_clears_stale_navigation_only_surface_headers() {
    let mut injector = NoiseInjector::new(single_mode_profile("cors"), 1);
    let mut headers = vec![
        ("Sec-Fetch-User".to_string(), "?1".to_string()),
        ("Upgrade-Insecure-Requests".to_string(), "1".to_string()),
    ];

    injector.inject(&mut headers);

    assert_eq!(header_value(&headers, "sec-fetch-mode"), Some("cors"));
    assert_eq!(header_value(&headers, "sec-fetch-dest"), Some("empty"));
    assert_eq!(header_value(&headers, "sec-fetch-site"), Some("cross-site"));
    assert_eq!(header_value(&headers, "sec-fetch-user"), None);
    assert_eq!(header_value(&headers, "upgrade-insecure-requests"), None);
}

#[test]
fn inject_chrome_emits_canonical_client_hints() {
    let mut injector = make_injector();
    let mut headers = Vec::new();
    injector.inject(&mut headers);

    let sec_ch_ua = header_value(&headers, "sec-ch-ua");
    let expected_sec_ch_ua = canonical_header(StealthProfile::ChromeWindowsStable, "Sec-CH-UA");
    assert_eq!(sec_ch_ua, Some(expected_sec_ch_ua.as_str()));
    assert!(sec_ch_ua.is_some_and(|value| value.contains("131")));
    assert!(!sec_ch_ua.is_some_and(|value| value.contains("\"130\"")));
    let expected_platform =
        canonical_header(StealthProfile::ChromeWindowsStable, "Sec-CH-UA-Platform");
    let expected_mobile = canonical_header(StealthProfile::ChromeWindowsStable, "Sec-CH-UA-Mobile");
    assert_eq!(
        header_value(&headers, "sec-ch-ua-platform"),
        Some(expected_platform.as_str())
    );
    assert_eq!(
        header_value(&headers, "sec-ch-ua-mobile"),
        Some(expected_mobile.as_str())
    );
}

#[test]
fn explicit_custom_client_hint_override_is_preserved() {
    let profile = BehavioralProfile {
        name: "custom_chromium",
        stealth_profile: None,
        accept_language_variants: vec![("en-US,en;q=0.9", 1.0)],
        user_agent_pool: vec!["Mozilla/5.0 (Windows NT 10.0) Chrome/1.0 Safari/537.36"],
        referer_pool: vec![""],
        timing: (100.0, 10.0),
        sec_fetch_mode: vec!["navigate"],
        emit_client_hints: true,
        sec_ch_ua: Some(r#""Custom Browser";v="1""#),
    };
    let mut injector = NoiseInjector::new(profile, 7);
    let mut headers = Vec::new();
    injector.inject(&mut headers);

    assert_eq!(
        header_value(&headers, "sec-ch-ua"),
        Some(r#""Custom Browser";v="1""#)
    );
    assert_eq!(header_value(&headers, "sec-ch-ua-mobile"), Some("?0"));
    assert_eq!(
        header_value(&headers, "sec-ch-ua-platform"),
        Some("\"Windows\"")
    );
}

#[test]
fn typed_stealth_profile_drives_session_catalog_over_user_agent_guess() {
    let profile = BehavioralProfile {
        name: "typed_override",
        stealth_profile: Some(StealthProfile::ChromeAndroid),
        accept_language_variants: vec![("en-US,en;q=0.9", 1.0)],
        user_agent_pool: vec![profile_user_agent(StealthProfile::ChromeWindowsStable)],
        referer_pool: vec![""],
        timing: (100.0, 10.0),
        sec_fetch_mode: vec!["navigate"],
        emit_client_hints: true,
        sec_ch_ua: Some(r#""Typed Browser";v="1""#),
    };
    let mut injector = NoiseInjector::new(profile, 7);
    let mut headers = Vec::new();
    injector.inject(&mut headers);

    assert_eq!(header_value(&headers, "sec-ch-ua-mobile"), Some("?1"));
    assert_eq!(
        header_value(&headers, "sec-ch-ua-platform"),
        Some("\"Android\"")
    );
}

#[test]
fn inject_firefox_no_client_hints() {
    let mut injector = NoiseInjector::new(BehavioralProfile::firefox_eu(), 42);
    let mut headers = Vec::new();
    injector.inject(&mut headers);
    assert!(!headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("sec-ch-ua")));
}

#[test]
fn inject_does_not_overwrite_attack_headers() {
    let mut injector = make_injector();
    let mut headers = vec![("x-attack-payload".to_string(), "' OR 1=1--".to_string())];
    injector.inject(&mut headers);
    assert!(headers
        .iter()
        .any(|(name, value)| name == "x-attack-payload" && value == "' OR 1=1--"));
}

#[test]
fn inject_replaces_existing_user_agent() {
    let mut injector = make_injector();
    let mut headers = vec![("user-agent".to_string(), "wafrift-bot/1.0".to_string())];
    injector.inject(&mut headers);
    let ua = header_value(&headers, "user-agent").expect("user-agent header");
    assert_ne!(ua, "wafrift-bot/1.0");
    assert!(ua.contains("Mozilla"), "new UA must be browser-like: {ua}");
}

#[test]
fn inject_preserves_existing_accept_headers_case_insensitively() {
    let mut injector = make_injector();
    let mut headers = vec![
        ("ACCEPT".to_string(), "application/json".to_string()),
        ("Accept-Encoding".to_string(), "identity".to_string()),
    ];

    injector.inject(&mut headers);

    assert_eq!(header_value(&headers, "accept"), Some("application/json"));
    assert_eq!(header_value(&headers, "accept-encoding"), Some("identity"));
    assert_eq!(
        headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("accept"))
            .count(),
        1
    );
    assert_eq!(
        headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
            .count(),
        1
    );
}

#[test]
fn inject_user_agent_is_stable_across_calls() {
    let mut injector = make_injector();
    let mut first_headers = Vec::new();
    let mut second_headers = Vec::new();
    injector.inject(&mut first_headers);
    injector.inject(&mut second_headers);
    assert_eq!(
        header_value(&first_headers, "user-agent"),
        header_value(&second_headers, "user-agent")
    );
}

#[test]
fn inject_accept_language_is_stable() {
    let mut injector = make_injector();
    let mut first_headers = Vec::new();
    let mut second_headers = Vec::new();
    injector.inject(&mut first_headers);
    injector.inject(&mut second_headers);
    assert_eq!(
        header_value(&first_headers, "accept-language"),
        header_value(&second_headers, "accept-language")
    );
}

#[test]
fn timing_is_positive_and_capped() {
    let mut injector = make_injector();
    for _ in 0..20 {
        let timing = injector.next_timing();
        assert!(timing.sleep_ms >= 50, "sleep must be >= 50ms");
        assert!(timing.sleep_ms <= 8000, "sleep must be <= 8000ms");
    }
}

#[test]
fn request_count_increments() {
    let mut injector = make_injector();
    assert_eq!(injector.request_count(), 0);
    let mut headers = Vec::new();
    injector.inject(&mut headers);
    assert_eq!(injector.request_count(), 1);
    injector.inject(&mut headers);
    assert_eq!(injector.request_count(), 2);
}

#[test]
fn set_current_url_affects_referer() {
    let mut injector = make_injector();
    injector.set_current_url("https://target.example.com/page");
    let mut headers = Vec::new();
    injector.inject(&mut headers);
    let mut saw_referer = false;
    for _ in 0..30 {
        let mut next_headers = Vec::new();
        injector.inject(&mut next_headers);
        if let Some(value) = header_value(&next_headers, "referer") {
            if value.contains("target.example.com") {
                saw_referer = true;
                break;
            }
        }
    }
    assert!(saw_referer);
}
#[test]
fn inject_unknown_ua_does_not_forge_windows_platform_hint() {
    let profile = BehavioralProfile {
        name: "unknown_ua_profile",
        stealth_profile: None,
        accept_language_variants: vec![("en-US,en;q=0.9", 1.0)],
        user_agent_pool: vec!["Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"],
        referer_pool: vec![""],
        timing: (100.0, 10.0),
        sec_fetch_mode: vec!["navigate"],
        emit_client_hints: true,
        sec_ch_ua: Some("\"Firefox\";v=\"132\""),
    };
    let mut injector = NoiseInjector::new(profile, 0x1234);
    let mut headers = Vec::new();
    injector.inject(&mut headers);

    assert_eq!(
        header_value(&headers, "sec-ch-ua-platform"),
        Some("\"Linux\""),
        "Firefox Linux UA should resolve Linux platform hint, never forge Windows"
    );

    let unknown_profile = BehavioralProfile {
        name: "unknown_bot_profile",
        stealth_profile: None,
        accept_language_variants: vec![("en-US,en;q=0.9", 1.0)],
        user_agent_pool: vec!["CustomScanner/1.0"],
        referer_pool: vec![""],
        timing: (100.0, 10.0),
        sec_fetch_mode: vec!["navigate"],
        emit_client_hints: true,
        sec_ch_ua: Some("\"CustomBot\";v=\"1\""),
    };
    let mut unknown_injector = NoiseInjector::new(unknown_profile, 0x1234);
    let mut unknown_headers = Vec::new();
    unknown_injector.inject(&mut unknown_headers);

    assert_eq!(
        header_value(&unknown_headers, "sec-ch-ua-platform"),
        None,
        "Unknown OS UA should omit platform hint, never forge Windows"
    );
}
