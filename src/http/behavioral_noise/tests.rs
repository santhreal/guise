use super::*;
use crate::fingerprint::profile_facts;

fn make_injector() -> NoiseInjector {
    NoiseInjector::new(BehavioralProfile::chrome_us(), 0xDEAD_BEEF)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn canonical_header(profile: StealthProfile, name: &str) -> String {
    browser_request_headers(profile, BrowserRequestKind::Navigation)
        .into_iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .unwrap_or_else(|| panic!("{profile:?} missing canonical {name} header"))
        .value
}

fn single_mode_profile(mode: &'static str) -> BehavioralProfile {
    BehavioralProfile {
        name: "single_mode",
        stealth_profile: Some(StealthProfile::ChromeWindowsStable),
        accept_language_variants: vec![("en-US,en;q=0.9", 1.0)],
        user_agent_pool: vec![profile_user_agent(StealthProfile::ChromeWindowsStable)],
        referer_pool: vec![""],
        timing: (100.0, 10.0),
        sec_fetch_mode: vec![mode],
        emit_client_hints: true,
        sec_ch_ua: None,
    }
}

#[path = "tests/injection.rs"]
mod injection;
#[path = "tests/profiles.rs"]
mod profiles;
