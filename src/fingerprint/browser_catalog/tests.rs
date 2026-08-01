use super::*;
use crate::fingerprint::profile_user_agent;

#[test]
fn profiles_populated() {
    assert!(PROFILES.len() >= 6);
}

#[test]
fn random_profile_returns_valid() {
    let profile = random_profile().expect("PROFILES array is empty");
    assert!(!profile.user_agent.is_empty());
    assert!(!profile.accept.is_empty());
}

#[test]
fn apply_profile_sets_headers() {
    let mut headers = vec![("User-Agent".into(), "old".into())];
    apply_profile(&mut headers, &PROFILES[0]);
    let ua = headers
        .iter()
        .find(|(key, _)| key == "User-Agent")
        .expect("user-agent header");
    assert!(ua.1.contains("Chrome"));
    assert_eq!(
        headers
            .iter()
            .filter(|(key, _)| key == "User-Agent")
            .count(),
        1
    );
}

#[test]
fn each_profile_has_unique_ua() {
    let uas: Vec<&str> = PROFILES.iter().map(|profile| profile.user_agent).collect();
    let unique: std::collections::HashSet<&&str> = uas.iter().collect();
    assert_eq!(uas.len(), unique.len(), "Duplicate User-Agent found");
}

#[test]
fn canonical_profiles_delegate_headers_to_stealth() {
    for (name, stealth_profile) in [
        ("chrome-windows", StealthProfile::ChromeWindowsStable),
        ("chrome-mac", StealthProfile::ChromeMacStable),
        ("firefox-windows", StealthProfile::FirefoxWindows),
        ("firefox-linux", StealthProfile::FirefoxLinux),
        ("safari-mac", StealthProfile::SafariMacStable),
        ("edge-windows", StealthProfile::EdgeWindowsStable),
    ] {
        let profile = PROFILES
            .iter()
            .find(|profile| profile.name == name)
            .unwrap_or_else(|| panic!("missing canonical profile {name}"));
        let facts = profile_facts(stealth_profile);

        assert_eq!(
            profile.user_agent,
            profile_user_agent(stealth_profile),
            "{name} User-Agent drifted from stealth"
        );
        assert_eq!(profile.accept, facts.accept, "{name} Accept drifted");
        assert_eq!(
            profile.accept_language, facts.accept_language,
            "{name} Accept-Language drifted"
        );
        assert_eq!(
            profile.accept_encoding, facts.accept_encoding,
            "{name} Accept-Encoding drifted"
        );
    }
}

#[test]
fn apply_profile_replaces_all_fingerprint_headers() {
    let mut headers = vec![
        ("user-agent".into(), "old-ua".into()),
        ("accept".into(), "old-accept".into()),
        ("accept-language".into(), "old-lang".into()),
        ("accept-encoding".into(), "old-enc".into()),
        ("sec-fetch-site".into(), "old-site".into()),
        ("sec-fetch-mode".into(), "old-mode".into()),
        ("sec-fetch-dest".into(), "old-dest".into()),
        ("other-header".into(), "keep-me".into()),
    ];
    apply_profile(&mut headers, &PROFILES[0]);

    for header in [
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
    ] {
        assert_eq!(
            headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(header))
                .count(),
            1,
            "{header} should appear once"
        );
    }

    assert!(headers
        .iter()
        .any(|(key, value)| key == "other-header" && value == "keep-me"));
}

#[test]
fn apply_profile_case_insensitive_replacement() {
    let mut headers = vec![
        ("USER-AGENT".into(), "old".into()),
        ("Accept".into(), "old".into()),
        ("sec-FETCH-MODE".into(), "old".into()),
    ];
    apply_profile(&mut headers, &PROFILES[0]);
    for header in ["user-agent", "accept", "sec-fetch-mode"] {
        assert_eq!(
            headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(header))
                .count(),
            1,
            "{header} should appear once"
        );
    }
}

#[test]
fn apply_profile_adds_missing_headers() {
    let mut headers = vec![("other".into(), "value".into())];
    apply_profile(&mut headers, &PROFILES[0]);
    for header in [
        "User-Agent",
        "Accept",
        "Accept-Language",
        "Accept-Encoding",
        "Sec-Fetch-Site",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Dest",
    ] {
        assert!(
            headers.iter().any(|(key, _)| key == header),
            "missing {header}"
        );
    }
}

#[test]
fn canonical_profiles_use_stealth_header_source() {
    let mut headers = Vec::new();
    apply_profile(&mut headers, &PROFILES[0]);

    assert!(
        headers.iter().any(|(key, _)| key == "Sec-CH-UA"),
        "chrome profile should use stealth canonical Client Hint headers"
    );
    assert!(
        headers
            .iter()
            .any(|(key, value)| key == "Upgrade-Insecure-Requests" && value == "1"),
        "chrome profile should use stealth canonical navigation headers"
    );
}

#[test]
fn unknown_profile_uses_legacy_fields() {
    let profile = HeaderProfile {
        name: "custom",
        user_agent: "custom-agent",
        accept: "custom-accept",
        accept_language: "zz-ZZ",
        accept_encoding: "identity",
        sec_fetch_site: "same-origin",
        sec_fetch_mode: "cors",
        sec_fetch_dest: "empty",
    };
    let mut headers = Vec::new();
    apply_profile(&mut headers, &profile);

    assert!(headers
        .iter()
        .any(|(key, value)| key == "User-Agent" && value == "custom-agent"));
    assert!(headers
        .iter()
        .all(|(key, _)| !key.eq_ignore_ascii_case("sec-ch-ua")));
}
