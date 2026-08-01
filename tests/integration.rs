//! Integration tests: end-to-end exercises of the public API surface.
//!
//! These tests drive the library at the level an external crate
//! consumer would, combining multiple subsystems together and
//! verifying that the whole pipeline works.

// G258/G259: gated via `required-features = ["fingerprint", "human", "rotation"]`
// in Cargo.toml so single-feature builds skip it rather than failing on absent
// modules.

use guise::fingerprint::bundle::validate_overrides;
use guise::fingerprint::{
    profile_js, profile_to_overrides, ProfileBundle, ProfileError, StealthProfile,
};
use guise::human::keystroke::{plan_keystrokes, TypingPlan};
use guise::rotation::all_profiles;
use rand::{rngs::StdRng, SeedableRng};

// ── End-to-end: ProfileBundle → validate → profile_js ──

/// Full pipeline: create a bundle, validate it, materialise overrides,
/// generate JS, and check the JS contains all expected browser signals.
#[test]
fn chrome_windows_bundle_full_pipeline() {
    let bundle = ProfileBundle::chrome_131_windows();
    bundle.validate_browser_coherence().unwrap();

    let ov = profile_to_overrides(&bundle.browser);
    validate_overrides(&ov).unwrap();

    let js = profile_js(&ov);

    // The JS must encode UA, platform, brands, touch capability, WebGL. Window
    // and screen DIMENSIONS are deliberately NOT encoded: a JS getter cannot move
    // the real layout/matchMedia/screen, so pinning them is a contradiction (see
    // overrides.rs and tests/geometry_live.rs), they pass through to the native,
    // self-consistent values. maxTouchPoints IS encoded (a real capability signal).
    assert!(js.contains("Windows NT"), "UA not in JS");
    assert!(js.contains("Win32"), "platform not in JS");
    assert!(js.contains("Google Chrome"), "Chrome brand not in JS");
    assert!(js.contains("maxTouchPoints"), "touch capability not in JS");
    assert!(
        !js.contains("'innerWidth'") && !js.contains("'outerWidth'"),
        "window dimensions must NOT be pinned (matchMedia/clientWidth contradiction)"
    );
    assert!(js.contains("0x9245"), "WebGL vendor constant not in JS");
    assert!(js.contains("Intel(R) Iris"), "WebGL renderer not in JS");
    assert!(js.contains("hardwareConcurrency"), "HWC override not in JS");
    assert!(
        js.contains("deviceMemory"),
        "deviceMemory override not in JS"
    );
}

#[test]
fn firefox_linux_bundle_full_pipeline() {
    let bundle = ProfileBundle::firefox_133();
    bundle.validate_browser_coherence().unwrap();

    let ov = profile_to_overrides(&bundle.browser);
    validate_overrides(&ov).unwrap();

    let js = profile_js(&ov);

    assert!(js.contains("Firefox/"), "Firefox UA not in JS");
    assert!(js.contains("Linux x86_64"), "platform not in JS");
    // Firefox profile generates the brands conditional but the runtime
    // check (brands.length > 0) will be false at runtime.
    assert!(js.contains("brands.length > 0"), "brands guard must appear");
    // Firefox personas NEVER carry the JS WebGL getParameter override: the
    // engine prefs (`build_user_js`'s `webgl.override-unmasked-*`) cover every
    // realm, including a Web Worker's OffscreenCanvas WebGL that a window-realm
    // getter cannot reach (the worker leaked the real host GPU; confirmed live,
    // tests/worker_webgl_cross_os_live.rs). For a matched-host persona like
    // FirefoxLinux the prefs stay unset too (empty renderer), so the adapter is
    // Gecko's own sanitized one, whose pixels actually match.
    assert!(
        !js.contains("UNMASKED_RENDERER"),
        "Firefox personas must not pin WebGL from JS (engine prefs own that layer)"
    );
    assert!(
        !js.contains("getParameter"),
        "Firefox personas must not wrap getParameter (engine prefs own that layer)"
    );
}

#[test]
fn safari_mac_bundle_full_pipeline() {
    // ProfileBundle::safari_17_5() uses SafariMacStable with Apple M2 GPU.
    let bundle = ProfileBundle::safari_17_5();
    bundle.validate_browser_coherence().unwrap();

    let ov = profile_to_overrides(&bundle.browser);
    validate_overrides(&ov).unwrap();

    let js = profile_js(&ov);
    assert!(js.contains("Safari"), "Safari UA not in JS");
    assert!(js.contains("Apple"), "Apple WebGL renderer not in JS");
    assert!(js.contains("MacIntel"), "macOS platform not in JS");
}

// ── End-to-end: all bundled profiles pass coherence ──

#[test]
fn all_tier_a_bundles_validate_without_error() {
    let bundles = [
        ProfileBundle::chrome_131_macos(),
        ProfileBundle::chrome_131_windows(),
        ProfileBundle::firefox_133(),
        ProfileBundle::firefox_133_windows(),
        ProfileBundle::safari_17_5(),
        ProfileBundle::edge_131(),
    ];
    for bundle in bundles {
        bundle
            .validate_browser_coherence()
            .unwrap_or_else(|e| panic!("bundle {:?} failed: {e}", bundle.browser));
    }
}

// ── End-to-end: ProfileBundle coherence errors propagate correctly ──

#[test]
fn bundle_validate_browser_coherence_surfaces_error() {
    // Manually construct an incoherent bundle (Windows UA + MacIntel platform).
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    ov.platform = "MacIntel".into();
    let err = validate_overrides(&ov).unwrap_err();
    // The error message must be informative.
    let msg = err.to_string();
    assert!(
        msg.contains("MacIntel") || msg.contains("Windows") || msg.contains("platform"),
        "error message '{msg}' should mention the incoherence"
    );
}

#[test]
fn direct3d_renderer_on_non_windows_platform_is_rejected() {
    // The Windows mirror of the Apple-GPU rule: a Direct3D/D3D11 renderer (the
    // Windows ANGLE backend) on a non-Win32 platform is a cross-surface tell.
    // Start from a coherent macOS persona and graft a Windows GPU renderer.
    let mut ov = profile_to_overrides(&StealthProfile::FirefoxMacStable);
    assert_eq!(ov.platform, "MacIntel", "precondition: macOS persona");
    ov.webgl_vendor = "Google Inc. (NVIDIA)".into();
    ov.webgl_renderer =
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)".into();
    let err = validate_overrides(&ov).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Direct3D") && msg.contains("MacIntel"),
        "error '{msg}' should name the Direct3D-on-non-Windows incoherence"
    );
}

// ── End-to-end: keystroke planner → timing pipeline ──

/// Drive the keystroke planner for a realistic login form fill:
/// username + space + password analog.
#[test]
fn login_form_keystroke_plan_end_to_end() {
    let username = "user@example";
    let password = "hunter2abc";

    let mut rng = StdRng::seed_from_u64(12345);
    let plan = TypingPlan {
        typo_probability: 0.02,
        thinking_pause_probability: 0.08,
        ..Default::default()
    };

    // Type username.
    let username_keys = plan_keystrokes(username, plan, &mut rng);
    // At near-zero typo probability there should be at least as many
    // keystrokes as characters.
    assert!(username_keys.len() >= username.chars().count());
    // First gap must be zero.
    assert_eq!(username_keys[0].gap_ms_before, 0);

    // Type password.
    let password_keys = plan_keystrokes(password, plan, &mut rng);
    assert!(password_keys.len() >= password.chars().count());
    assert_eq!(password_keys[0].gap_ms_before, 0);

    // Real chars in username plan must spell out the username.
    let real_username: String = username_keys
        .iter()
        .filter(|k| !k.is_correction)
        .map(|k| k.ch)
        .collect();
    assert_eq!(real_username, username);

    let real_password: String = password_keys
        .iter()
        .filter(|k| !k.is_correction)
        .map(|k| k.ch)
        .collect();
    assert_eq!(real_password, password);
}

/// Typing a search query: hot bigrams should produce gaps < 170ms.
#[test]
fn search_query_hot_bigrams_produce_sub_200ms_gaps() {
    let query = "the answer";
    let mut rng = StdRng::seed_from_u64(7777);
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes(query, plan, &mut rng);
    // `t→h` is hot (60–100ms), `h→e` is hot (65–105ms).
    // Key[0]='t' gap=0, Key[1]='h', Key[2]='e'.
    assert_eq!(keys[1].gap_ms_before, {
        // The t→h bigram from the table.
        let g = keys[1].gap_ms_before;
        assert!((60..=100).contains(&g), "t→h gap {g} not in 60–100ms");
        g
    });
    assert!(
        keys[2].gap_ms_before >= 65 && keys[2].gap_ms_before <= 105,
        "h→e gap {} not in 65–105ms",
        keys[2].gap_ms_before
    );
}

// ── End-to-end: profile selection + JS generation for every profile ──

#[test]
fn every_profile_produces_valid_js_iife() {
    for p in all_profiles() {
        let ov = profile_to_overrides(p);

        // Must pass coherence check.
        validate_overrides(&ov).unwrap_or_else(|e| panic!("{p:?} coherence failed: {e}"));

        // Must produce valid-looking JS.
        let js = profile_js(&ov);
        assert!(
            js.trim_start().starts_with("(()"),
            "{p:?} JS does not start with IIFE"
        );
        assert!(
            js.contains("userAgent"),
            "{p:?} JS missing userAgent override"
        );
        assert!(
            js.contains("platform"),
            "{p:?} JS missing platform override"
        );
        assert!(
            js.contains("hardwareConcurrency"),
            "{p:?} JS missing hardwareConcurrency override"
        );
        // The WebGL getParameter constants appear only for non-Gecko personas:
        // Chrome/Safari are injected onto engines without
        // `webgl.override-unmasked-*` prefs, so the JS getter wrap is the only
        // spoof. Firefox personas deliberately omit the block because the
        // engine prefs cover realms (Web Workers) a window-realm getter cannot.
        let ua_is_firefox = ov.user_agent.contains("Firefox/");
        if ua_is_firefox {
            assert!(
                !js.contains("0x9245"),
                "{p:?} Firefox persona must not wrap getParameter in JS (engine prefs own WebGL)"
            );
        } else {
            assert!(
                js.contains("0x9245"),
                "{p:?} JS missing WebGL UNMASKED_VENDOR constant"
            );
            assert!(
                js.contains("0x9246"),
                "{p:?} JS missing WebGL UNMASKED_RENDERER constant"
            );
        }
    }
}

// ── End-to-end: ProfileError display messages are informative ──

#[test]
fn profile_error_incoherent_message_is_human_readable() {
    let err = ProfileError::Incoherent("UA claims Windows but platform is MacIntel".into());
    let msg = err.to_string();
    assert!(
        msg.contains("MacIntel"),
        "error message must include detail: {msg}"
    );
    assert!(msg.len() > 20, "error message suspiciously short: {msg}");
}

// ── End-to-end: deterministic output for fixed RNG seed ──

/// The keystroke planner must be deterministic: same seed → same output.
#[test]
fn keystroke_plan_is_deterministic_for_same_seed() {
    let text = "stealth test";
    let plan = TypingPlan {
        typo_probability: 0.05,
        thinking_pause_probability: 0.1,
        ..Default::default()
    };

    let mut rng1 = StdRng::seed_from_u64(42);
    let keys1 = plan_keystrokes(text, plan, &mut rng1);

    let mut rng2 = StdRng::seed_from_u64(42);
    let keys2 = plan_keystrokes(text, plan, &mut rng2);

    assert_eq!(
        keys1.len(),
        keys2.len(),
        "same seed must produce same length"
    );
    for (k1, k2) in keys1.iter().zip(keys2.iter()) {
        assert_eq!(k1.ch, k2.ch);
        assert_eq!(k1.hold_ms, k2.hold_ms);
        assert_eq!(k1.gap_ms_before, k2.gap_ms_before);
        assert_eq!(k1.is_correction, k2.is_correction);
    }
}

/// Different seeds must produce different outputs for non-trivial text
/// (statistical check: at least one gap value must differ).
#[test]
fn keystroke_plan_differs_for_different_seeds() {
    let text = "the quick brown fox";
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };

    let mut rng1 = StdRng::seed_from_u64(1);
    let keys1 = plan_keystrokes(text, plan, &mut rng1);

    let mut rng2 = StdRng::seed_from_u64(2);
    let keys2 = plan_keystrokes(text, plan, &mut rng2);

    // Same length (no typos/pauses don't change output length).
    assert_eq!(keys1.len(), keys2.len());
    // At least one gap value must differ (entropy check).
    let all_same = keys1
        .iter()
        .zip(keys2.iter())
        .all(|(k1, k2)| k1.gap_ms_before == k2.gap_ms_before && k1.hold_ms == k2.hold_ms);
    assert!(
        !all_same,
        "different RNG seeds should produce different timing"
    );
}

// ── End-to-end: Tier-A config → persona pool lifecycle ──

/// A `GuiseConfig` must convert into a working `PersonaPool`, and the pool's
/// capacity limit must be observable behavior (G264 / G281 / G283).
#[test]
fn config_drives_pool_lifecycle() {
    use guise::config::{GuiseConfig, RotationPolicyName};
    use guise::persona_pool::PersonaPool;

    let cfg = GuiseConfig::default()
        .with_rotation_policy(RotationPolicyName::PerTarget)
        .with_max_concurrent_sessions(2);
    let pool_cfg = cfg.to_pool_config();
    let mut pool = PersonaPool::new(pool_cfg);

    let a = pool.acquire("a.com").unwrap();
    let b = pool.acquire("b.com").unwrap();
    assert!(
        pool.acquire("c.com").is_err(),
        "capacity limit must block a third new session"
    );
    pool.release(a).unwrap();
    pool.release(b).unwrap();
}
