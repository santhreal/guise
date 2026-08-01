//! Canonical profile rotation for cross-plane stealth identity.
//!
//! Rotation is intentionally profile-level: HTTP headers, TLS impersonation,
//! viewport, WebGL, and browser JS overrides all derive from the selected
//! [`StealthProfile`] instead of rotating one surface independently.

use crate::fingerprint::{
    StealthProfile, ALL_PROFILES, DEFAULT_STEALTH_PROFILE, ROTATION_PROFILES,
};
use guise_profiles as profile_catalog;
use serde::{Deserialize, Serialize};

/// When and why to rotate the active stealth profile.
///
/// G223: rotation is a Tier-A config knob. The policy is deliberately coarse:
/// it decides *when* to rotate; the `ProfileCycle` decides *to what*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RotationPolicy {
    /// Never rotate (the same persona is used for the lifetime of the process).
    Never,
    /// Rotate once at session start, then keep that persona for the session.
    #[default]
    PerSession,
    /// Rotate whenever the target domain changes.
    PerTarget,
    /// Rotate every `n` requests.
    PerRequests(u64),
}

/// Mutable state tracked by a rotation policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationState {
    /// The last target string (usually a host or domain) seen by the policy.
    pub previous_target: Option<String>,
    /// Number of requests made with the current persona.
    pub request_count: u64,
}

impl RotationPolicy {
    /// Decide whether the caller should rotate to the next profile before issuing
    /// a request to `current_target`.
    ///
    /// * `Never`: always `false`.
    /// * `PerSession`: `true` only when `state` is fresh (`request_count == 0`).
    /// * `PerTarget`: `true` when `current_target` differs from `state.previous_target`.
    /// * `PerRequests(n)`: `true` every `n` requests (including the first).
    ///
    /// The caller is responsible for updating `state` after a rotation.
    #[must_use]
    pub fn should_rotate(&self, state: &RotationState, current_target: &str) -> bool {
        match self {
            RotationPolicy::Never => false,
            RotationPolicy::PerSession => {
                state.request_count == 0 && state.previous_target.is_none()
            }
            RotationPolicy::PerTarget => state
                .previous_target
                .as_deref()
                .map(|prev| prev != current_target)
                .unwrap_or(true),
            RotationPolicy::PerRequests(n) => {
                if *n == 0 {
                    false
                } else {
                    state.request_count.is_multiple_of(*n)
                }
            }
        }
    }

    /// Update `state` after a request has been issued (whether or not a rotation
    /// happened). This keeps request-count and target tracking accurate.
    pub fn record_request(&self, state: &mut RotationState, current_target: &str) {
        state.request_count += 1;
        state.previous_target = Some(current_target.to_string());
    }
}

const DESKTOP_HTTP_PROFILE_CYCLE: &[StealthProfile] = &[
    DEFAULT_STEALTH_PROFILE,
    StealthProfile::ChromeMacStable,
    StealthProfile::SafariMacStable,
    StealthProfile::FirefoxLinux,
    StealthProfile::FirefoxMacStable,
    StealthProfile::EdgeWindowsStable,
    StealthProfile::ChromeLinux,
];

const CHROMIUM_DESKTOP_PROFILE_CYCLE: &[StealthProfile] = &[
    DEFAULT_STEALTH_PROFILE,
    StealthProfile::ChromeMacStable,
    StealthProfile::ChromeLinux,
];

/// Profiles used by deterministic fleet rotation.
#[must_use]
pub const fn profiles() -> &'static [StealthProfile] {
    ROTATION_PROFILES
}

/// Every named profile in the canonical catalog.
///
/// Legacy compatibility personas are returned here even when they are excluded
/// from deterministic rotation.
#[must_use]
pub const fn all_profiles() -> &'static [StealthProfile] {
    ALL_PROFILES
}

/// Conservative desktop HTTP profiles for scanners that only rotate headers.
///
/// This avoids mobile/touch surfaces and uncommon Chromium derivative brands
/// while still covering Chrome, Edge, Safari, Firefox, Windows, macOS, and Linux.
#[must_use]
pub const fn desktop_http_profiles() -> &'static [StealthProfile] {
    DESKTOP_HTTP_PROFILE_CYCLE
}

/// Randomly select a conservative desktop HTTP profile.
///
/// This is the canonical selector for scanner `--random-user-agent` style
/// behavior: callers rotate whole browser profiles, not independent UA strings.
#[must_use]
pub fn random_desktop_http_profile() -> StealthProfile {
    crate::choice::random_item(desktop_http_profiles())
        .copied()
        .unwrap_or(DEFAULT_STEALTH_PROFILE)
}

/// Chromium desktop profiles safe for CDP `Network.setUserAgentOverride` paths.
#[must_use]
pub const fn chromium_desktop_profiles() -> &'static [StealthProfile] {
    CHROMIUM_DESKTOP_PROFILE_CYCLE
}

/// Stable lowercase profile name for operator-facing config.
#[must_use]
pub const fn profile_name(profile: StealthProfile) -> &'static str {
    profile_catalog::profile_name(profile)
}

/// Stable enum-style profile name for human-readable listings.
#[must_use]
pub const fn profile_display_name(profile: StealthProfile) -> &'static str {
    profile_catalog::profile_display_name(profile)
}

/// Resolve a config profile name or common alias to a canonical profile.
#[must_use]
pub fn named_profile(name: &str) -> Option<StealthProfile> {
    profile_catalog::named_profile(name)
}

/// Deterministically select a profile by index.
#[must_use]
pub fn profile_at(index: usize) -> StealthProfile {
    let profiles = profiles();
    profiles[index % profiles.len()]
}

/// Resolve an optional named profile, falling back to deterministic rotation.
#[must_use]
pub fn named_or_rotated(name: Option<&str>, index: usize) -> StealthProfile {
    name.and_then(named_profile)
        .unwrap_or_else(|| profile_at(index))
}

/// Infinite deterministic profile cycle.
#[derive(Debug, Clone)]
pub struct ProfileCycle {
    next_index: usize,
}

impl ProfileCycle {
    /// Start cycling at the beginning of the canonical profile list.
    #[must_use]
    pub const fn new() -> Self {
        Self { next_index: 0 }
    }

    /// Start cycling from a caller-provided offset.
    #[must_use]
    pub const fn from_index(next_index: usize) -> Self {
        Self { next_index }
    }
}

impl Default for ProfileCycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for ProfileCycle {
    type Item = StealthProfile;

    fn next(&mut self) -> Option<Self::Item> {
        let profile = profile_at(self.next_index);
        self.next_index = self.next_index.wrapping_add(1);
        Some(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_at_wraps_at_cycle_len() {
        assert_eq!(profile_at(0), profile_at(profiles().len()));
        assert_ne!(profile_at(0), profile_at(1));
    }

    #[test]
    fn aliases_resolve_to_stable_profiles() {
        assert_eq!(
            named_profile("chrome_131_windows"),
            Some(StealthProfile::ChromeWindowsStable)
        );
        assert_eq!(
            named_profile("safari"),
            Some(StealthProfile::SafariMacStable)
        );
        assert_eq!(
            named_profile("firefox-windows"),
            Some(StealthProfile::FirefoxWindows)
        );
        assert_eq!(
            named_profile("chrome-win"),
            Some(StealthProfile::ChromeWindowsStable)
        );
        assert_eq!(
            named_profile("ChromeMacStable"),
            Some(StealthProfile::ChromeMacStable)
        );
        assert_eq!(named_profile("ie11"), Some(StealthProfile::Ie11Windows));
        assert_eq!(
            named_profile("chrome-windows-legacy-96"),
            Some(StealthProfile::ChromeWindowsLegacy96)
        );
        assert_eq!(named_profile("unknown"), None);
    }

    #[test]
    fn every_profile_has_names_that_resolve() {
        for profile in all_profiles() {
            assert_eq!(named_profile(profile_name(*profile)), Some(*profile));
            assert!(!profile_display_name(*profile).is_empty());
        }
    }

    #[test]
    fn full_catalog_includes_explicit_only_legacy_profiles() {
        assert!(all_profiles().contains(&StealthProfile::ChromeWindowsLegacy96));
        assert!(all_profiles().contains(&StealthProfile::Ie11Windows));
        assert!(!profiles().contains(&StealthProfile::ChromeWindowsLegacy96));
        assert!(!profiles().contains(&StealthProfile::Ie11Windows));
    }

    #[test]
    fn constrained_rotation_pools_are_subsets_of_full_rotation() {
        for profile in desktop_http_profiles() {
            assert!(profiles().contains(profile));
        }
        for profile in chromium_desktop_profiles() {
            assert!(desktop_http_profiles().contains(profile));
        }
    }

    #[test]
    fn random_desktop_http_profile_stays_in_constrained_pool() {
        for _ in 0..128 {
            assert!(desktop_http_profiles().contains(&random_desktop_http_profile()));
        }
    }

    #[test]
    fn cycle_is_infinite_and_ordered() {
        let mut cycle = ProfileCycle::from_index(profiles().len() - 1);
        assert_eq!(cycle.next(), Some(StealthProfile::SamsungInternetAndroid));
        assert_eq!(cycle.next(), Some(DEFAULT_STEALTH_PROFILE));
    }

    #[test]
    fn cycle_default_starts_at_zero() {
        let cycle = ProfileCycle::default();
        assert_eq!(cycle.next_index, 0);
    }

    #[test]
    fn cycle_new_starts_at_zero() {
        let cycle = ProfileCycle::new();
        assert_eq!(cycle.next_index, 0);
    }

    #[test]
    fn cycle_from_index_wraps_on_next() {
        let mut cycle = ProfileCycle::from_index(usize::MAX);
        // usize::MAX + 1 wraps to 0
        let first = cycle.next().unwrap();
        assert_eq!(first, profile_at(usize::MAX));
        let second = cycle.next().unwrap();
        assert_eq!(second, profile_at(0));
    }

    #[test]
    fn named_or_rotated_prefers_name_when_given() {
        let rotated = named_or_rotated(None, 0);
        let named = named_or_rotated(Some("safari"), 0);
        assert_eq!(named, StealthProfile::SafariMacStable);
        assert_ne!(Some(rotated), named_profile("safari"));
    }

    #[test]
    fn named_or_rotated_falls_back_on_bad_name() {
        let fallback = named_or_rotated(Some("totally-invalid"), 3);
        assert_eq!(fallback, profile_at(3));
    }

    #[test]
    fn profile_name_is_lowercase_snake() {
        let name = profile_name(StealthProfile::ChromeWindowsStable);
        assert!(name.chars().all(|c| c.is_lowercase() || c == '_'));
    }

    #[test]
    fn profile_display_name_contains_browser_name() {
        let display = profile_display_name(StealthProfile::FirefoxLinux);
        assert!(display.contains("Firefox") || display.contains("firefox"));
    }

    #[test]
    fn desktop_http_profiles_excludes_mobile() {
        for profile in desktop_http_profiles() {
            let display = profile_display_name(*profile).to_lowercase();
            assert!(
                !display.contains("iphone"),
                "desktop pool should not contain iPhone"
            );
            assert!(
                !display.contains("ipad"),
                "desktop pool should not contain iPad"
            );
            assert!(
                !display.contains("android"),
                "desktop pool should not contain Android"
            );
        }
    }

    #[test]
    fn chromium_desktop_profiles_are_all_chromium() {
        for profile in chromium_desktop_profiles() {
            let display = profile_display_name(*profile).to_lowercase();
            assert!(
                display.contains("chrome") || display.contains("chromium"),
                "{display} is not a Chromium profile"
            );
        }
    }

    #[test]
    fn all_profiles_is_nonempty() {
        assert!(!all_profiles().is_empty());
    }

    #[test]
    fn profiles_is_nonempty() {
        assert!(!profiles().is_empty());
    }

    #[test]
    fn named_profile_case_insensitive_aliases() {
        assert_eq!(named_profile("CHROME"), named_profile("chrome"));
        assert_eq!(named_profile("Firefox"), named_profile("firefox"));
    }

    #[test]
    fn profile_at_zero_is_first_in_profiles() {
        assert_eq!(profile_at(0), profiles()[0]);
    }

    // ── G221/G222/G224: rotation produces coherent, fully-layered personas ───

    #[test]
    fn every_rotated_profile_builds_a_coherent_bundle() {
        // G221: rotation must yield a persona whose JS + TLS + network layers
        // all agree; ProfileBundle::for_browser enforces this.
        for profile in profiles() {
            let bundle = crate::fingerprint::ProfileBundle::for_browser(*profile);
            assert_eq!(bundle.browser, *profile);
        }
    }

    #[test]
    fn rotation_changes_js_identity_across_profiles() {
        // G222: consecutive rotated profiles must reflect the NEW persona in the
        // JS layer (user agent string).
        let mut cycle = ProfileCycle::new();
        let first = cycle.next().unwrap();
        let second = cycle.next().unwrap();
        let ua_a = crate::fingerprint::profile_user_agent(first);
        let ua_b = crate::fingerprint::profile_user_agent(second);
        assert_ne!(ua_a, ua_b, "rotation must change the JS-layer identity");
    }

    #[cfg(all(feature = "http-headers", feature = "browser"))]
    #[test]
    fn rotation_changes_transport_fingerprint_across_different_families() {
        // G222: rotation across browser families must change the transport-layer
        // fingerprint. We deliberately pick profiles known to differ in TLS/H2.
        let chrome = StealthProfile::ChromeWindowsStable;
        let firefox = StealthProfile::FirefoxLinux;
        let chrome_bundle = crate::fingerprint::ProfileBundle::for_browser(chrome);
        let firefox_bundle = crate::fingerprint::ProfileBundle::for_browser(firefox);
        let chrome_fp = crate::probe::compute_transport_fingerprint(&chrome_bundle);
        let firefox_fp = crate::probe::compute_transport_fingerprint(&firefox_bundle);
        assert_ne!(
            chrome_fp.ja4, firefox_fp.ja4,
            "Chrome vs Firefox rotation must change JA4"
        );
        assert_ne!(
            chrome_fp.h2_akamai, firefox_fp.h2_akamai,
            "Chrome vs Firefox rotation must change H2 fingerprint"
        );
    }

    #[test]
    fn rotation_never_mixes_persona_a_js_with_persona_b_tls() {
        // G224: a bundle built from profile A must not contain profile B's
        // identity signals anywhere in the assembled persona.
        let a = StealthProfile::ChromeWindowsStable;
        let b = StealthProfile::FirefoxLinux;
        let bundle_a = crate::fingerprint::ProfileBundle::for_browser(a);
        let ua_b = crate::fingerprint::profile_user_agent(b);
        let js_a = crate::fingerprint::profile_js(&crate::fingerprint::profile_to_overrides(&a));
        assert!(
            !js_a.contains(ua_b),
            "Chrome bundle's profile_js must not contain the Firefox UA"
        );
        // The bundle's browser field is the single source of identity.
        assert_eq!(bundle_a.browser, a);
    }

    // ── G223: rotation policy decisions ─────────────────────────────────────

    #[test]
    fn policy_never_never_rotates() {
        let mut state = RotationState::default();
        let policy = RotationPolicy::Never;
        assert!(!policy.should_rotate(&state, "example.com"));
        state.request_count = 100;
        state.previous_target = Some("other.com".to_string());
        assert!(!policy.should_rotate(&state, "example.com"));
    }

    #[test]
    fn policy_per_session_rotates_once() {
        let mut state = RotationState::default();
        let policy = RotationPolicy::PerSession;
        assert!(policy.should_rotate(&state, "example.com"));
        // Simulate rotation + first request.
        policy.record_request(&mut state, "example.com");
        assert!(!policy.should_rotate(&state, "example.com"));
        assert!(!policy.should_rotate(&state, "other.com"));
        assert_eq!(state.request_count, 1);
    }

    #[test]
    fn policy_per_target_rotates_on_target_change() {
        let mut state = RotationState::default();
        let policy = RotationPolicy::PerTarget;
        assert!(policy.should_rotate(&state, "a.com"));
        policy.record_request(&mut state, "a.com");
        assert!(!policy.should_rotate(&state, "a.com"));
        assert!(policy.should_rotate(&state, "b.com"));
        policy.record_request(&mut state, "b.com");
        assert!(!policy.should_rotate(&state, "b.com"));
        // Returning to a previous target still counts as a change.
        assert!(policy.should_rotate(&state, "a.com"));
    }

    #[test]
    fn policy_per_requests_rotates_every_n() {
        let mut state = RotationState::default();
        let policy = RotationPolicy::PerRequests(3);
        // Request count 0 => rotate, then 1 and 2 => no rotate, 3 => rotate.
        assert!(policy.should_rotate(&state, "x"));
        policy.record_request(&mut state, "x");
        assert!(!policy.should_rotate(&state, "x"));
        policy.record_request(&mut state, "x");
        assert!(!policy.should_rotate(&state, "x"));
        policy.record_request(&mut state, "x");
        assert!(policy.should_rotate(&state, "x"));
        policy.record_request(&mut state, "x");
        assert!(!policy.should_rotate(&state, "x"));
    }

    #[test]
    fn policy_per_requests_zero_is_noop() {
        let mut state = RotationState::default();
        let policy = RotationPolicy::PerRequests(0);
        assert!(!policy.should_rotate(&state, "x"));
        state.request_count = 99;
        assert!(!policy.should_rotate(&state, "x"));
    }

    #[test]
    fn policy_per_requests_one_rotates_every_request() {
        let mut state = RotationState::default();
        let policy = RotationPolicy::PerRequests(1);
        for i in 0..5 {
            assert!(policy.should_rotate(&state, "x"), "rotate on request {i}");
            policy.record_request(&mut state, "x");
        }
    }

    #[test]
    fn default_policy_is_per_session() {
        assert_eq!(RotationPolicy::default(), RotationPolicy::PerSession);
    }

    #[test]
    fn policy_record_request_updates_target_and_count() {
        let mut state = RotationState::default();
        RotationPolicy::PerTarget.record_request(&mut state, "example.com");
        assert_eq!(state.request_count, 1);
        assert_eq!(state.previous_target.as_deref(), Some("example.com"));
    }
}
