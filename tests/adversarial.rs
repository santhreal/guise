//! Adversarial tests: hostile, malformed, boundary, and edge inputs.
//!
//! These tests exercise what happens when the public API receives
//! unexpected or hostile data rather than the happy-path inputs
//! tested in the unit suite.
//!
//! G258/G259: gated via `required-features = ["fingerprint", "human", "rotation"]`
//! in Cargo.toml so single-feature builds skip it rather than failing on absent
//! modules.

use guise::fingerprint::bundle::validate_overrides;
use guise::fingerprint::{profile_js, profile_to_overrides, ProfileError, StealthProfile};
use guise::human::keystroke::{
    bigram_gap, hold_envelope, plan_keystrokes, qwerty_neighbour, TypingPlan,
    COLD_BIGRAM_GAP_MAX_MS, COLD_BIGRAM_GAP_MIN_MS,
};
use guise::rotation::all_profiles;
use rand::{rngs::StdRng, Rng, SeedableRng};

// ── ProfileOverrides coherence: all the ways validate_overrides must reject ──

#[test]
fn windows_ua_with_non_win32_platform_rejected() {
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    // Poison the platform while keeping the UA.
    ov.platform = "Linux x86_64".into();
    let err = validate_overrides(&ov).unwrap_err();
    assert!(
        matches!(err, ProfileError::Incoherent(_)),
        "expected Incoherent, got {err:?}"
    );
}

#[test]
fn macos_ua_with_win32_platform_rejected() {
    let mut ov = profile_to_overrides(&StealthProfile::ChromeMacStable);
    ov.platform = "Win32".into();
    assert!(validate_overrides(&ov).is_err());
}

#[test]
fn android_ua_without_mobile_flag_rejected() {
    let mut ov = profile_to_overrides(&StealthProfile::ChromeAndroid);
    ov.mobile = false; // contradicts the "Android" UA
    let err = validate_overrides(&ov).unwrap_err();
    assert!(matches!(err, ProfileError::Incoherent(_)));
}

#[test]
fn chromium_ua_without_brands_rejected() {
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    ov.brands.clear();
    let err = validate_overrides(&ov).unwrap_err();
    assert!(matches!(err, ProfileError::Incoherent(_)));
}

#[test]
fn firefox_ua_with_brands_rejected() {
    let mut ov = profile_to_overrides(&StealthProfile::FirefoxLinux);
    // Inject fake brands - Firefox never ships Client Hints.
    ov.brands.push(("Google Chrome".into(), "130".into()));
    let err = validate_overrides(&ov).unwrap_err();
    assert!(matches!(err, ProfileError::Incoherent(_)));
}

#[test]
fn ios_ua_with_mac_os_x_not_rejected_as_macos_desktop() {
    // iPhone UA contains "like Mac OS X" but platform should be iPhone,
    // NOT MacIntel. The coherence check has a special iOS bypass.
    let ov = profile_to_overrides(&StealthProfile::SafariIphone);
    // Should pass - the iOS exemption is critical.
    validate_overrides(&ov).expect("SafariIphone overrides must be self-consistent");
}

#[test]
fn ipad_ua_with_mac_os_x_not_rejected_as_macos_desktop() {
    let ov = profile_to_overrides(&StealthProfile::SafariIpad);
    validate_overrides(&ov).expect("SafariIpad overrides must be self-consistent");
}

// ── profile_js: output must be non-empty and contain key identifiers ──

#[test]
fn profile_js_contains_ua_string() {
    let ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    let js = profile_js(&ov);
    // The generated JS must contain the literal UA string.
    assert!(
        js.contains("Windows NT"),
        "profile_js must embed the UA in the JS snippet"
    );
}

#[test]
fn profile_js_never_empty() {
    for p in all_profiles() {
        let js = profile_js(&profile_to_overrides(p));
        assert!(!js.is_empty(), "{p:?} profile_js must be non-empty");
        assert!(js.len() > 100, "{p:?} profile_js is suspiciously short");
    }
}

#[test]
fn profile_js_with_empty_languages_still_valid() {
    // Edge case: nobody should ship empty languages, but the function
    // must not panic.
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    ov.languages.clear();
    let js = profile_js(&ov);
    // serde_json serialises an empty vec as "[]".
    assert!(js.contains("[]"));
}

#[test]
fn profile_js_with_empty_brands_still_valid() {
    // Clearing brands on a Chrome profile simulates future broken state;
    // profile_js must not panic.
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    ov.brands.clear();
    let js = profile_js(&ov);
    // X071/Law-6: prove the empty-brands input still yields a STRUCTURALLY VALID
    // IIFE that preserves the rest of the persona (not merely a non-empty string).
    assert!(
        js.trim_start().starts_with("(()") && js.contains("})()"),
        "empty brands must still emit a well-formed IIFE"
    );
    assert!(
        js.contains("Windows NT") && js.contains("Win32"),
        "clearing brands must not drop the UA/platform overrides"
    );
    // The userAgentData block is conditional on brands.length > 0.
    assert!(js.contains("brands.length > 0"));
}

// ── bigram_gap: boundary characters ──

#[test]
fn bigram_gap_tab_treated_as_space() {
    // Tab is the "whitespace" branch alongside space.
    let (lo, hi) = bigram_gap('a', '\t');
    assert_eq!(lo, guise::human::keystroke::SPACE_GAP_MIN_MS);
    assert_eq!(hi, guise::human::keystroke::SPACE_GAP_MAX_MS);
}

#[test]
fn bigram_gap_digit_letter_falls_through_to_cold() {
    // digit→letter is neither digit-pair nor hot bigram → cold envelope.
    let (lo, hi) = bigram_gap('3', 'x');
    assert_eq!(lo, COLD_BIGRAM_GAP_MIN_MS);
    assert_eq!(hi, COLD_BIGRAM_GAP_MAX_MS);
}

#[test]
fn bigram_gap_letter_digit_falls_through_to_cold() {
    let (lo, hi) = bigram_gap('a', '9');
    assert_eq!(lo, COLD_BIGRAM_GAP_MIN_MS);
    assert_eq!(hi, COLD_BIGRAM_GAP_MAX_MS);
}

#[test]
fn bigram_gap_all_envelopes_have_positive_range() {
    // Every possible call to bigram_gap must return lo <= hi and both > 0.
    let sample_pairs: &[(char, char)] = &[
        ('a', 'b'),
        ('t', 'h'),
        ('q', 'z'),
        ('5', '7'),
        ('3', 'a'),
        ('a', ' '),
        ('a', '\t'),
        ('Z', 'X'),
        ('M', 'N'),
    ];
    for &(prev, next) in sample_pairs {
        let (lo, hi) = bigram_gap(prev, next);
        assert!(lo > 0, "({prev},{next}) lo must be positive");
        assert!(lo <= hi, "({prev},{next}) lo must be ≤ hi");
    }
}

// ── hold_envelope: boundary character classes ──

#[test]
fn hold_envelope_all_printable_ascii_non_zero() {
    for ch in (32u8..=126u8).map(|b| b as char) {
        let (lo, hi) = hold_envelope(ch);
        assert!(lo > 0, "hold lo for {ch:?} must be > 0");
        assert!(lo <= hi, "hold lo must be ≤ hi for {ch:?}");
    }
}

#[test]
fn hold_envelope_uppercase_held_longer_than_lowercase() {
    for (lower, upper) in ('a'..='z').zip('A'..='Z') {
        let (lo_l, _) = hold_envelope(lower);
        let (lo_u, _) = hold_envelope(upper);
        assert!(
            lo_u > lo_l,
            "uppercase {upper} must have higher lo than {lower}"
        );
    }
}

// ── plan_keystrokes: hostile inputs ──

#[test]
fn plan_keystrokes_empty_string_returns_empty() {
    let mut rng = StdRng::seed_from_u64(0);
    let keys = plan_keystrokes("", TypingPlan::default(), &mut rng);
    assert!(
        keys.is_empty(),
        "empty input must yield empty keystroke plan"
    );
}

#[test]
fn plan_keystrokes_single_char_no_gap() {
    let mut rng = StdRng::seed_from_u64(0);
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("x", plan, &mut rng);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].ch, 'x');
    assert_eq!(keys[0].gap_ms_before, 0, "first char must have zero gap");
    assert!(!keys[0].is_correction);
}

#[test]
fn plan_keystrokes_all_spaces() {
    let mut rng = StdRng::seed_from_u64(1);
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("   ", plan, &mut rng);
    // Spaces are not alphabetic so no typo injection.
    assert_eq!(keys.len(), 3);
    // All chars should be spaces.
    assert!(keys.iter().all(|k| k.ch == ' '));
}

#[test]
fn plan_keystrokes_all_digits() {
    let mut rng = StdRng::seed_from_u64(2);
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("1234567890", plan, &mut rng);
    assert_eq!(keys.len(), 10);
    assert!(keys.iter().all(|k| !k.is_correction));
}

#[test]
fn plan_keystrokes_hold_ms_within_envelope() {
    let mut rng = StdRng::seed_from_u64(5);
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("Hello World 123!", plan, &mut rng);
    for k in &keys {
        if k.is_correction {
            continue; // correction events have their own envelopes tested elsewhere
        }
        let (lo, hi) = hold_envelope(k.ch);
        assert!(
            k.hold_ms >= lo && k.hold_ms <= hi,
            "hold_ms {} for {:?} outside envelope ({lo}, {hi})",
            k.hold_ms,
            k.ch
        );
    }
}

#[test]
fn plan_keystrokes_gap_ms_within_envelope_for_non_corrections() {
    let mut rng = StdRng::seed_from_u64(6);
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    // Use a pure-lowercase string to stay in hot/cold bigram territory.
    let text = "the quick brown fox";
    let chars: Vec<char> = text.chars().collect();
    let keys = plan_keystrokes(text, plan, &mut rng);
    assert_eq!(keys.len(), chars.len());
    // First keystroke is always 0.
    assert_eq!(keys[0].gap_ms_before, 0);
    // Every subsequent gap must be within the bigram envelope.
    for (i, k) in keys[1..].iter().enumerate() {
        let (lo, hi) = bigram_gap(chars[i], chars[i + 1]);
        assert!(
            k.gap_ms_before >= lo && k.gap_ms_before <= hi,
            "gap {} for {:?}→{:?} outside ({lo},{hi})",
            k.gap_ms_before,
            chars[i],
            chars[i + 1]
        );
    }
}

#[test]
fn plan_keystrokes_zero_typo_prob_no_corrections() {
    let mut rng = StdRng::seed_from_u64(99);
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("abcdefghij", plan, &mut rng);
    assert!(keys.iter().all(|k| !k.is_correction));
}

#[test]
fn plan_keystrokes_real_chars_never_marked_correction() {
    let mut rng = StdRng::seed_from_u64(42);
    let plan = TypingPlan {
        typo_probability: 1.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("abc", plan, &mut rng);
    // For each triplet (wrong, BS, real), the real char must not be marked.
    let real_keys: Vec<_> = keys.iter().filter(|k| !k.is_correction).collect();
    assert_eq!(real_keys.len(), 3);
    for (k, expected) in real_keys.iter().zip(['a', 'b', 'c']) {
        assert_eq!(k.ch, expected);
    }
}

// ── qwerty_neighbour: edge seed values ──

#[test]
fn qwerty_neighbour_seed_wraps_around_neighbour_list() {
    // rng_seed is u8, so 255 must still yield a valid neighbour.
    let n = qwerty_neighbour('a', 255);
    assert!(n.is_some());
}

#[test]
fn qwerty_neighbour_non_letter_inputs_return_none() {
    let non_letters: &[char] = &['0', '9', '!', '@', '\n', ' ', '\t', '-', '_'];
    for &ch in non_letters {
        assert!(
            qwerty_neighbour(ch, 0).is_none(),
            "qwerty_neighbour({ch:?}, 0) should be None"
        );
    }
}

// ── Oracle / transport / behavioral adversarial checks (G212) ──────────────

#[test]
fn behavioral_fingerprint_extreme_seeds_do_not_panic() {
    // Adversarial: very large / boundary seeds must still produce a deterministic
    // fingerprint without overflow or panic.
    use guise::probe::compute_behavioral_fingerprint;
    for seed in [0u64, 1, u64::MAX, u64::MAX - 1] {
        let _ = compute_behavioral_fingerprint(seed);
    }
}

#[test]
fn transport_capture_for_safari_has_no_h2_but_still_has_tls_and_tcp() {
    // Safari has no measured H2 target in tls_targets, so the transport capture
    // must still surface JA3/JA4/JA4T/p0f and simply omit the H2 fields.
    use guise::fingerprint::{ProfileBundle, StealthProfile};
    use guise::probe::transport_capture;
    let bundle = ProfileBundle::for_browser(StealthProfile::SafariMacStable);
    let cap = transport_capture(&bundle, "safari");
    let names: std::collections::HashSet<&str> =
        cap.surfaces.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains("transport.ja3"));
    assert!(names.contains("transport.ja4"));
    assert!(names.contains("transport.ja4t"));
    assert!(names.contains("transport.p0f_signature"));
    assert!(!names.contains("transport.h2_akamai"));
    assert!(!names.contains("transport.h2_peet"));
}

#[test]
fn full_stack_compare_handles_label_mismatch_gracefully() {
    // Different labels across layer captures should not panic; the JS labels
    // become the report labels.
    use guise::fingerprint::{ProfileBundle, StealthProfile};
    use guise::probe::{behavioral_capture, full_stack_compare, transport_capture};
    let js_a = guise::probe::Capture {
        label: "stock".into(),
        surfaces: vec![],
    };
    let js_b = guise::probe::Capture {
        label: "disguise".into(),
        surfaces: vec![],
    };
    let bundle = ProfileBundle::for_browser(StealthProfile::FirefoxLinux);
    let transport_a = transport_capture(&bundle, "ta");
    let transport_b = transport_capture(&bundle, "tb");
    let behavioral_a = behavioral_capture(1, "ba");
    let behavioral_b = behavioral_capture(1, "bb");
    let report = full_stack_compare(
        &js_a,
        &transport_a,
        &behavioral_a,
        &js_b,
        &transport_b,
        &behavioral_b,
    );
    assert_eq!(report.label_a, "stock");
    assert_eq!(report.label_b, "disguise");
}

// ── fuzz-style parser resilience (G266) ──

/// Random byte strings fed to the Tier-B TOML loader must not panic.
#[cfg(all(feature = "tier-b-toml", feature = "http"))]
#[test]
fn tier_b_toml_parser_does_not_panic_on_random_input() {
    use std::io::Write;

    let mut rng = StdRng::seed_from_u64(12345);
    let dir = std::env::temp_dir().join(format!("guise-adv-fuzz-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    for i in 0..256usize {
        // Generate a short random payload, biased toward printable ASCII but
        // with occasional raw bytes.
        let payload: Vec<u8> = (0..64)
            .map(|_| {
                let roll = rng.gen::<u8>();
                if roll < 200 {
                    b' ' + (rng.gen::<u8>() % 95)
                } else {
                    rng.gen::<u8>()
                }
            })
            .collect();
        let path = dir.join(format!("fuzz-{i}.toml"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&payload).unwrap();
        drop(f);

        // Must not panic; either Ok or Err is fine.
        let _ = guise::fingerprint::ProfileBundle::from_toml(&path);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The TLS profile parser must not panic on arbitrary profile names.
#[cfg(feature = "http")]
#[test]
fn tls_profile_parser_does_not_panic_on_random_names() {
    use guise::http::ImpersonateProfile;
    use rand::Rng;

    let mut rng = StdRng::seed_from_u64(54321);
    for _ in 0..256 {
        let len = rng.gen_range(0..32);
        let name: String = (0..len).map(|_| rng.gen::<u8>() as char).collect();
        let _ = ImpersonateProfile::parse(&name);
    }
}

/// The header builder must produce a result for every shipped profile.
#[test]
fn header_builder_does_not_panic_for_any_profile() {
    use guise::http::headers::browser_profile;
    for profile in all_profiles() {
        let _ = browser_profile(*profile);
    }
}

// ── helpers ──
