use super::*;

#[test]
fn pair_for_name_recognises_canonical_aliases() {
    for alias in ["chrome", "chrome131", "Chrome", "edge131", "EDGE"] {
        assert_eq!(pair_for_name(alias).unwrap().0.family, "chrome");
    }
    for alias in ["firefox", "Firefox133", "FIREFOX"] {
        assert_eq!(pair_for_name(alias).unwrap().0.family, "firefox");
    }
    for alias in ["safari", "safari18", "Safari17_5"] {
        assert_eq!(pair_for_name(alias).unwrap().0.family, "safari");
    }
    assert!(pair_for_name("unknown-browser").is_none());
    assert!(pair_for_name("").is_none());
}

#[test]
fn pair_for_name_resolves_full_stealth_profile_aliases() {
    for alias in [
        "chrome-android",
        "chrome-linux",
        "brave",
        "opera",
        "samsung-internet",
    ] {
        assert_eq!(pair_for_name(alias).unwrap().0.family, "chrome");
    }
    for alias in ["firefox-windows", "firefox-linux", "firefox-macos"] {
        assert_eq!(pair_for_name(alias).unwrap().0.family, "firefox");
    }
    for alias in ["safari-iphone", "safari-ipad", "safari"] {
        assert_eq!(pair_for_name(alias).unwrap().0.family, "safari");
    }
    assert!(pair_for_name("ie11").is_none());
}

#[test]
fn pair_for_profile_maps_canonical_profiles_to_browser_family() {
    for profile in [
        StealthProfile::ChromeWindowsStable,
        StealthProfile::ChromeWindowsLegacy96,
        StealthProfile::ChromeMacStable,
        StealthProfile::EdgeWindowsStable,
        StealthProfile::ChromeAndroid,
        StealthProfile::ChromeLinux,
        StealthProfile::BraveWindows,
        StealthProfile::OperaWindows,
        StealthProfile::SamsungInternetAndroid,
    ] {
        assert_eq!(pair_for_profile(profile).unwrap().0.family, "chrome");
    }
    for profile in [
        StealthProfile::FirefoxLinux,
        StealthProfile::FirefoxWindows,
        StealthProfile::FirefoxMacStable,
    ] {
        assert_eq!(pair_for_profile(profile).unwrap().0.family, "firefox");
    }
    for profile in [
        StealthProfile::SafariIphone,
        StealthProfile::SafariIpad,
        StealthProfile::SafariMacStable,
    ] {
        assert_eq!(pair_for_profile(profile).unwrap().0.family, "safari");
    }
    assert!(pair_for_profile(StealthProfile::Ie11Windows).is_none());
}

#[test]
fn header_order_and_h2_profile_pair_share_family_string() {
    for alias in ["chrome", "firefox", "safari"] {
        let (header_order, h2_profile) = pair_for_name(alias).unwrap();
        assert_eq!(header_order.family, h2_profile.family);
    }
}

#[test]
fn every_persona_transport_pair_family_matches_its_user_agent_browser() {
    // Generalises `pair_for_profile_maps_canonical_profiles_to_browser_family` from a
    // hand-maintained profile list into a UA-DERIVED, fail-closed sweep over the
    // canonical `ALL_PROFILES`. The transport pair (HeaderOrder + H2Profile) a persona
    // emits MUST belong to the same browser family its User-Agent advertises, or the
    // wire shows e.g. a Firefox UA over Chrome's H2 SETTINGS + header order, a
    // cross-layer split. The expected family is read from the persona's own UA via
    // `user_agent_facts().browser` (not string-matching): Chromium-based browsers
    // (Chrome/Edge/Opera/Samsung, and Brave, which has no distinct UA token and
    // parses as Chrome) share the "chrome" transport family; Firefox→"firefox";
    // Safari→"safari"; Internet Explorer (the IE11 persona) intentionally has NO
    // modern transport pair. A persona whose UA is Unknown, or whose pair presence
    // disagrees with its family, fails CLOSED, so a newly-added persona can never be
    // silently left without a coherent transport pair (Law 10).
    use crate::fingerprint::{
        profile_user_agent, user_agent_facts, UserAgentBrowser, ALL_PROFILES,
    };

    for &profile in ALL_PROFILES {
        let ua = profile_user_agent(profile);
        let expected_family = match user_agent_facts(ua).browser {
            UserAgentBrowser::Chrome
            | UserAgentBrowser::Edge
            | UserAgentBrowser::Opera
            | UserAgentBrowser::SamsungInternet => Some("chrome"),
            UserAgentBrowser::Firefox => Some("firefox"),
            UserAgentBrowser::Safari => Some("safari"),
            UserAgentBrowser::InternetExplorer => None,
            UserAgentBrowser::Unknown => panic!(
                "{profile:?}: UA {ua:?} parses to an Unknown browser, cannot resolve a \
                 coherent transport family; classify it before shipping"
            ),
        };
        match (pair_for_profile(profile), expected_family) {
            (Some((header, h2)), Some(fam)) => {
                assert_eq!(
                    header.family, fam,
                    "{profile:?}: header-order family {:?} != UA browser family {fam:?} (UA {ua:?})",
                    header.family
                );
                assert_eq!(
                    h2.family, fam,
                    "{profile:?}: H2 family {:?} != UA browser family {fam:?} (UA {ua:?})",
                    h2.family
                );
            }
            (None, None) => {} // IE11: no modern transport pair, as intended
            (Some((header, _)), None) => panic!(
                "{profile:?}: UA browser has no transport family yet a {:?} pair resolved",
                header.family
            ),
            (None, Some(fam)) => panic!(
                "{profile:?}: UA advertises {fam:?} but pair_for_profile returns NO transport pair"
            ),
        }
    }
}
