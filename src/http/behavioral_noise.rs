//! Browser-shaped behavioral HTTP header and timing noise.
//!
//! This module builds coherent session headers from canonical stealth browser
//! profiles: stable User-Agent, stable Accept-Language, browser Accept and
//! Accept-Encoding values, Sec-Fetch metadata, optional Chromium Client Hints,
//! organic Referer choices, and log-normal inter-request timing samples.

use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::choice::{chance_with_rng, random_item_with_rng, weighted_index_by_with_rng};
use crate::fingerprint::{
    infer_profile_from_user_agent, profile_user_agent, user_agent_facts, StealthProfile,
    ACCEPT_ENCODING_HEADER, ACCEPT_HEADER, ACCEPT_LANGUAGE_HEADER, SEC_FETCH_DEST_HEADER,
    SEC_FETCH_MODE_HEADER, SEC_FETCH_SITE_HEADER, SEC_FETCH_USER_HEADER,
    UPGRADE_INSECURE_REQUESTS_HEADER, USER_AGENT_HEADER,
};
use crate::http::headers::{browser_request_headers, BrowserRequestKind, HeaderPair};
use crate::sampling::standard_normal;

/// Behavioral browser profile for a browser, OS, locale, and navigation mix.
#[derive(Debug, Clone)]
pub struct BehavioralProfile {
    /// Stable profile name.
    pub name: &'static str,
    /// Canonical stealth profile backing the built-in browser identity.
    ///
    /// Custom behavioral profiles that intentionally supply their own
    /// `user_agent_pool` can leave this as `None`; those profiles use the
    /// legacy User-Agent fallback for family inference.
    pub stealth_profile: Option<StealthProfile>,
    /// Accept-Language header values, weighted by population share.
    pub accept_language_variants: Vec<(&'static str, f64)>,
    /// User-Agent strings for this browser family.
    pub user_agent_pool: Vec<&'static str>,
    /// Referer base URLs for organic navigation simulations.
    pub referer_pool: Vec<&'static str>,
    /// Inter-request timing as `(mean_ms, std_ms)`.
    pub timing: (f64, f64),
    /// Sec-Fetch-Mode values typical for this browser.
    pub sec_fetch_mode: Vec<&'static str>,
    /// Whether to include Chromium Client Hint headers.
    pub emit_client_hints: bool,
    /// Optional explicit Sec-CH-UA override for custom Chromium profiles.
    pub sec_ch_ua: Option<&'static str>,
}

impl BehavioralProfile {
    /// Chrome on Windows, US locale.
    #[must_use]
    pub fn chrome_us() -> Self {
        Self {
            name: "chrome_windows_us",
            stealth_profile: Some(StealthProfile::ChromeWindowsStable),
            accept_language_variants: vec![
                ("en-US,en;q=0.9", 0.70),
                ("en-US,en;q=0.9,es;q=0.8", 0.10),
                ("en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7", 0.05),
                ("en-US,en;q=0.9,fr;q=0.8", 0.05),
                ("en-US,en;q=0.9,de;q=0.8", 0.05),
                ("en-US,en;q=0.8", 0.05),
            ],
            user_agent_pool: vec![profile_user_agent(StealthProfile::ChromeWindowsStable)],
            referer_pool: vec![
                "https://www.google.com/",
                "https://www.bing.com/",
                "https://duckduckgo.com/",
                "https://www.google.com/search?q=site",
                "",
            ],
            timing: (850.0, 320.0),
            sec_fetch_mode: vec!["navigate", "cors", "no-cors", "same-origin"],
            emit_client_hints: true,
            sec_ch_ua: None,
        }
    }

    /// Firefox on Linux, European mixed locale.
    #[must_use]
    pub fn firefox_eu() -> Self {
        Self {
            name: "firefox_linux_eu",
            stealth_profile: Some(StealthProfile::FirefoxLinux),
            accept_language_variants: vec![
                ("de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7", 0.30),
                ("fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", 0.20),
                ("es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7", 0.15),
                ("it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7", 0.10),
                ("nl-NL,nl;q=0.9,en;q=0.8", 0.10),
                ("en-GB,en;q=0.9", 0.15),
            ],
            user_agent_pool: vec![profile_user_agent(StealthProfile::FirefoxLinux)],
            referer_pool: vec![
                "https://www.google.de/",
                "https://www.google.fr/",
                "https://www.google.es/",
                "https://duckduckgo.com/",
                "https://search.yahoo.com/",
                "",
            ],
            timing: (1100.0, 450.0),
            sec_fetch_mode: vec!["navigate", "cors", "same-origin"],
            emit_client_hints: false,
            sec_ch_ua: None,
        }
    }

    /// Safari on macOS, US locale.
    #[must_use]
    pub fn safari_us() -> Self {
        Self {
            name: "safari_macos_us",
            stealth_profile: Some(StealthProfile::SafariMacStable),
            accept_language_variants: vec![
                ("en-US,en;q=0.9", 0.80),
                ("en-US,en;q=0.9,es;q=0.8", 0.10),
                ("en-US,en;q=0.9,fr;q=0.8", 0.05),
                ("en-US,en;q=0.9,zh-TW;q=0.8", 0.05),
            ],
            user_agent_pool: vec![profile_user_agent(StealthProfile::SafariMacStable)],
            referer_pool: vec![
                "https://www.google.com/",
                "https://www.bing.com/",
                "",
                "https://t.co/",
                "https://l.instagram.com/",
            ],
            timing: (750.0, 280.0),
            sec_fetch_mode: vec!["navigate", "same-origin"],
            emit_client_hints: false,
            sec_ch_ua: None,
        }
    }

    /// Mobile Chrome on Android, global mixed locale.
    #[must_use]
    pub fn chrome_android() -> Self {
        Self {
            name: "chrome_android",
            stealth_profile: Some(StealthProfile::ChromeAndroid),
            accept_language_variants: vec![
                ("en-US,en;q=0.9", 0.40),
                ("zh-CN,zh;q=0.9", 0.20),
                ("hi-IN,hi;q=0.9,en;q=0.8", 0.10),
                ("pt-BR,pt;q=0.9,en;q=0.8", 0.10),
                ("ar,en;q=0.9", 0.10),
                ("ru-RU,ru;q=0.9,en;q=0.8", 0.10),
            ],
            user_agent_pool: vec![profile_user_agent(StealthProfile::ChromeAndroid)],
            referer_pool: vec![
                "https://www.google.com/",
                "https://m.facebook.com/",
                "https://t.co/",
                "https://l.instagram.com/",
                "",
            ],
            timing: (1200.0, 600.0),
            sec_fetch_mode: vec!["navigate", "cors"],
            emit_client_hints: true,
            sec_ch_ua: None,
        }
    }
}

/// Recommended inter-request timing for one request in a sequence.
#[derive(Debug, Clone, Copy)]
pub struct TimingProfile {
    /// Recommended sleep before this request, in milliseconds.
    pub sleep_ms: u64,
    /// Whether this request is marked as a below-mean burst.
    pub is_burst: bool,
}

/// Stateful behavioral noise injector.
#[derive(Debug, Clone)]
pub struct NoiseInjector {
    profile: BehavioralProfile,
    rng: StdRng,
    current_url: Option<String>,
    request_count: u32,
    session_user_agent: String,
    session_accept_language: String,
}

impl NoiseInjector {
    /// Build an injector from a behavioral profile and deterministic RNG seed.
    #[must_use]
    pub fn new(profile: BehavioralProfile, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let ua = sample_weighted_str(&profile.user_agent_pool, &mut rng);
        let al = sample_accept_language(&profile.accept_language_variants, &mut rng);
        Self {
            profile,
            rng,
            current_url: None,
            request_count: 0,
            session_user_agent: ua,
            session_accept_language: al,
        }
    }

    /// Inject behavioral headers into `headers`.
    ///
    /// Existing headers with the same name are replaced for identity and
    /// navigation metadata. Caller-supplied unrelated headers are preserved.
    pub fn inject(&mut self, headers: &mut Vec<(String, String)>) {
        self.request_count += 1;
        let canonical_profile = self.canonical_profile_for_session();
        let request_kind = self.sample_request_kind();
        let canonical_headers = browser_request_headers(canonical_profile, request_kind);

        clear_request_surface_headers(headers);
        self.inject_catalog_surface_headers(headers, &canonical_headers);

        let referer = self.sample_referer();
        if !referer.is_empty() {
            set_header(headers, "referer", &referer);
        }

        self.inject_client_hints(headers, &canonical_headers);

        if self.request_count == 1 || chance_with_rng(0.15, &mut self.rng) {
            set_header(headers, "cache-control", "max-age=0");
        }
    }

    /// Generate a timing recommendation for the next request.
    #[must_use]
    pub fn next_timing(&mut self) -> TimingProfile {
        let (mean, std) = self.profile.timing;
        let sigma = (((std / mean).powi(2) + 1.0).ln()).sqrt();
        let mu = mean.ln() - sigma.powi(2) / 2.0;
        let z = standard_normal(&mut self.rng);
        let sample_ms = (mu + sigma * z).exp().clamp(50.0, 8000.0);
        let sleep_ms = sample_ms as u64;
        TimingProfile {
            sleep_ms,
            is_burst: sample_ms < mean * 0.5,
        }
    }

    fn canonical_profile_for_session(&self) -> StealthProfile {
        if let Some(profile) = self.profile.stealth_profile {
            return profile;
        }

        infer_profile_from_user_agent(&self.session_user_agent)
            .unwrap_or(StealthProfile::ChromeWindowsStable)
    }

    fn sample_referer(&mut self) -> String {
        if self.request_count == 1 {
            let pool = &self.profile.referer_pool;
            return sample_weighted_str(pool, &mut self.rng);
        }
        if chance_with_rng(0.70, &mut self.rng) {
            if let Some(cur) = &self.current_url {
                return cur.clone();
            }
        }
        sample_weighted_str(&self.profile.referer_pool, &mut self.rng)
    }

    fn sample_request_kind(&mut self) -> BrowserRequestKind {
        let mode = sample_weighted_str(&self.profile.sec_fetch_mode, &mut self.rng);
        match mode.as_str() {
            "navigate" => {
                if self.current_url.is_none() {
                    BrowserRequestKind::Navigation
                } else if chance_with_rng(0.6, &mut self.rng) {
                    BrowserRequestKind::SameOriginNavigation
                } else {
                    BrowserRequestKind::CrossSiteNavigation
                }
            }
            "cors" => {
                if self.current_url.is_some() && chance_with_rng(0.6, &mut self.rng) {
                    BrowserRequestKind::SameOriginFetch
                } else {
                    BrowserRequestKind::CrossSiteFetch
                }
            }
            "same-origin" => BrowserRequestKind::SameOriginModeFetch,
            "no-cors" => BrowserRequestKind::ImageSubresource,
            _ => BrowserRequestKind::Navigation,
        }
    }

    fn inject_catalog_surface_headers(
        &self,
        headers: &mut Vec<(String, String)>,
        canonical_headers: &[HeaderPair],
    ) {
        for header in canonical_headers {
            if is_client_hint_header(header.name) {
                continue;
            }

            if header.name.eq_ignore_ascii_case(USER_AGENT_HEADER) {
                set_header(headers, header.name, &self.session_user_agent);
                continue;
            }

            if header.name.eq_ignore_ascii_case(ACCEPT_LANGUAGE_HEADER) {
                set_header(headers, header.name, &self.session_accept_language);
                continue;
            }

            if (header.name.eq_ignore_ascii_case(ACCEPT_HEADER)
                || header.name.eq_ignore_ascii_case(ACCEPT_ENCODING_HEADER))
                && has_header(headers, header.name)
            {
                continue;
            }

            set_header(headers, header.name, &header.value);
        }
    }

    fn inject_client_hints(&self, headers: &mut Vec<(String, String)>, canonical: &[HeaderPair]) {
        if !self.profile.emit_client_hints {
            return;
        }

        if let Some(ua_hint) = self.profile.sec_ch_ua {
            set_header(headers, "sec-ch-ua", ua_hint);
            let mobile = self
                .canonical_client_hint(canonical, "Sec-CH-UA-Mobile")
                .map(str::to_string)
                .unwrap_or_else(|| self.mobile_hint_from_user_agent().to_string());
            let platform = self
                .canonical_client_hint(canonical, "Sec-CH-UA-Platform")
                .map(str::to_string)
                .unwrap_or_else(|| self.platform_hint_from_user_agent().to_string());
            set_header(headers, "sec-ch-ua-mobile", &mobile);
            set_header(headers, "sec-ch-ua-platform", &platform);
            return;
        }

        for header in canonical
            .iter()
            .filter(|header| header.name.starts_with("Sec-CH-UA"))
        {
            set_header(headers, header.name, &header.value);
        }
    }

    fn canonical_client_hint<'a>(
        &self,
        canonical: &'a [HeaderPair],
        name: &str,
    ) -> Option<&'a str> {
        canonical
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    fn platform_hint_from_user_agent(&self) -> &'static str {
        user_agent_facts(&self.session_user_agent)
            .client_hint_platform_value()
            .unwrap_or("\"Windows\"")
    }

    fn mobile_hint_from_user_agent(&self) -> &'static str {
        user_agent_facts(&self.session_user_agent).client_hint_mobile_value()
    }

    /// Update the simulated current URL used for Referer chains.
    pub fn set_current_url(&mut self, url: impl Into<String>) {
        self.current_url = Some(url.into());
    }

    /// Current request count in this session.
    #[must_use]
    pub fn request_count(&self) -> u32 {
        self.request_count
    }

    /// Behavioral profile name.
    #[must_use]
    pub fn profile_name(&self) -> &'static str {
        self.profile.name
    }
}

fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    for (n, v) in headers.iter_mut() {
        if n.eq_ignore_ascii_case(name) {
            *v = value.to_string();
            return;
        }
    }
    headers.push((name.to_string(), value.to_string()));
}

fn clear_request_surface_headers(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| !is_request_surface_header(name));
}

fn is_request_surface_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(UPGRADE_INSECURE_REQUESTS_HEADER)
        || name.eq_ignore_ascii_case(SEC_FETCH_DEST_HEADER)
        || name.eq_ignore_ascii_case(SEC_FETCH_MODE_HEADER)
        || name.eq_ignore_ascii_case(SEC_FETCH_SITE_HEADER)
        || name.eq_ignore_ascii_case(SEC_FETCH_USER_HEADER)
}

fn is_client_hint_header(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("sec-ch-ua")
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers
        .iter()
        .any(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
}

fn sample_weighted_str<S: AsRef<str>>(pool: &[S], rng: &mut StdRng) -> String {
    random_item_with_rng(pool, rng)
        .map(AsRef::as_ref)
        .unwrap_or_default()
        .to_string()
}

fn sample_accept_language(variants: &[(&'static str, f64)], rng: &mut StdRng) -> String {
    weighted_index_by_with_rng(variants, |(_, weight)| *weight, rng)
        .map(|index| variants[index].0.to_string())
        .unwrap_or_else(|| "en-US,en;q=0.9".to_string())
}

#[cfg(test)]
#[path = "behavioral_noise/tests.rs"]
mod tests;
