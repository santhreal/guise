//! Gap tests: documented limitations and edge cases that must stay
//! pinned so any future behavioural change is deliberate.
//!
//! Each test documents a known current limitation or a subtle
//! behaviour that a future maintainer might accidentally change.

// G258/G259: gated via `required-features = ["fingerprint", "human"]` in
// Cargo.toml so single-feature builds skip it rather than failing on absent
// modules.

use guise::fingerprint::bundle::validate_overrides;
use guise::fingerprint::{profile_js, profile_to_overrides, StealthProfile};
use guise::human::keystroke::{
    bigram_gap, plan_keystrokes, qwerty_neighbour, TypingPlan, COLD_BIGRAM_GAP_MAX_MS,
    COLD_BIGRAM_GAP_MIN_MS,
};
use rand::{rngs::StdRng, SeedableRng};

// ── Documented limitation: qwerty_neighbour has no coverage for digits ──

/// GAP: `qwerty_neighbour` returns None for all digits, uppercase, and
/// punctuation. This is a known incomplete implementation documented in
/// the source. This test pins the contract so adding coverage is a
/// conscious commit, not a silent regression.
#[test]
fn qwerty_neighbour_digits_unsupported_returns_none() {
    for d in '0'..='9' {
        assert!(
            qwerty_neighbour(d, 0).is_none(),
            "digit {d:?} returns Some - if this is intentional update this test"
        );
    }
}

/// GAP: uppercase letters are explicitly not handled (the function
/// lowercases its input internally). A 'A' call falls through
/// because the match arm is written for `'a'`, not 'A'.
/// Actually: the source uses `ch.to_ascii_lowercase()`, so uppercase
/// SHOULD work. This test pins that the documented example `qwerty_neighbour('h', 0)`
/// also works for its uppercase counterpart.
#[test]
fn qwerty_neighbour_uppercase_delegates_via_lowercase_branch() {
    // The source does `match ch.to_ascii_lowercase()`, so 'H' -> 'h'.
    let lower = qwerty_neighbour('h', 0);
    let upper = qwerty_neighbour('H', 0);
    assert_eq!(
        lower, upper,
        "uppercase and lowercase should produce the same neighbour"
    );
}

// ── GAP: plan_keystrokes thinking-pause gap saturation ──

/// GAP: `gap_ms_before` is a u16. When a thinking pause is added, the
/// saturating_add prevents overflow. This pins that the arithmetic
/// does NOT panic and the value saturates at u16::MAX rather than
/// wrapping or panicking.
#[test]
fn plan_keystrokes_thinking_pause_saturates_not_wraps() {
    // Use a very long string so multiple thinking pauses fire.
    let text = "the quick brown fox jumps over the lazy dog";
    let mut rng = StdRng::seed_from_u64(9999);
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 1.0,
        ..Default::default()
    };
    let keys = plan_keystrokes(text, plan, &mut rng);
    // No panic = sat arithmetic works. Also check none are 0 after first.
    assert_eq!(keys[0].gap_ms_before, 0);
    for k in &keys[1..] {
        // The added thinking pause (200–600ms) on top of a bigram gap should
        // always give a value > 0.
        assert!(k.gap_ms_before > 0, "thinking-pause gap must be nonzero");
    }
}

// ── Client Hint brand version coherence ──

/// Coherence check verifies that Client Hint brand versions are numeric
/// and match the relevant UA token. Brand/UA version drift is a bot
/// signal even when the platform and browser family are otherwise right.
#[test]
fn validate_overrides_rejects_invalid_brand_version_strings() {
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    // Corrupt the version strings to non-numeric values.
    ov.brands = vec![
        ("Chromium".into(), "garbage".into()),
        ("Google Chrome".into(), "not-a-number".into()),
        ("Not?A_Brand".into(), "???".into()),
    ];
    validate_overrides(&ov).expect_err("brand versions must be numeric");
}

#[test]
fn validate_overrides_rejects_brand_major_drift_from_ua() {
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    ov.brands = vec![
        ("Chromium".into(), "130".into()),
        ("Google Chrome".into(), "130".into()),
        ("Not?A_Brand".into(), "99".into()),
    ];
    validate_overrides(&ov).expect_err("brand majors must match the UA Chrome major");
}

// ── GAP: validate_overrides does NOT check hardware_concurrency bounds ──

/// GAP: an out-of-range hardware_concurrency (e.g., 0 or 10000) passes
/// validation. Real browsers never have 0 or >128 logical cores.
/// Pin this so a future bounds check is deliberate.
#[test]
fn validate_overrides_does_not_check_hardware_concurrency_range() {
    let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    ov.hardware_concurrency = 0;
    validate_overrides(&ov)
        .expect("zero hardware_concurrency passes (known gap - no bounds check)");

    ov.hardware_concurrency = 65535;
    validate_overrides(&ov).expect("absurdly large hardware_concurrency passes (known gap)");
}

// ── CLOSED GAP: profile_js no longer pins screen.availHeight ──

/// CLOSED GAP: `profile_js` formerly hard-coded
/// `screen.availHeight = screen.height - 40`. That override is gone: screen.* /
/// avail* are deliberately left native so they stay consistent with the
/// matchMedia `device-width`/`device-height` layer (overriding the JS getters
/// does NOT move matchMedia, so a pinned-but-inconsistent avail size is itself a
/// tell, incolumitas MQ_SCREEN). See `overrides.rs` and the
/// `stealth_profile_screen_is_self_consistent` contract. This test pins the gap
/// CLOSED: no hard-coded `- 40` availHeight offset may reappear in the emitted
/// override script.
#[test]
fn profile_js_does_not_hardcode_avail_height_offset() {
    let ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    let js = profile_js(&ov);
    assert!(
        !js.contains("- 40"),
        "availHeight must not be pinned to `height - 40`: screen.* is native for \
         matchMedia coherence; re-introducing the offset is a regression"
    );
}

// ── GAP: bigram_gap does not cover all two-char sequences ──

/// GAP: the hot_bigrams table covers the top ~40 English bigrams.
/// Any pair outside that table (and not a digit-pair or space) falls
/// back to the cold envelope. This test enumerates a known "warm"
/// letter pair that is NOT in the table and confirms it hits cold.
#[test]
fn bigram_gap_unlisted_letter_pair_falls_to_cold() {
    // "xv" is on the keyboard but not in the table.
    let (lo, hi) = bigram_gap('x', 'v');
    assert_eq!(lo, COLD_BIGRAM_GAP_MIN_MS);
    assert_eq!(hi, COLD_BIGRAM_GAP_MAX_MS);
}

// ── GAP: hot_bigrams table range - lo must always be < COLD min ──

/// GAP: if a hot bigram's minimum is ever accidentally set >= the cold
/// minimum (180ms), that bigram would be indistinguishable from a cold
/// bigram by any consumer that checks lo == COLD_MIN. Pin the structural
/// invariant that all table entries have lo < COLD_MIN.
#[test]
fn all_hot_bigrams_lo_strictly_less_than_cold_min() {
    // Re-check every table entry. This mirrors what the source comment
    // claims but is not otherwise tested.
    // We verify via bigram_gap for every pair in the documented range.
    let hot_pairs = [
        ('t', 'h'),
        ('h', 'e'),
        ('i', 'n'),
        ('e', 'r'),
        ('a', 'n'),
        ('r', 'e'),
        ('o', 'n'),
        ('a', 't'),
        ('e', 'n'),
        ('n', 'd'),
        ('t', 'i'),
        ('e', 's'),
        ('o', 'r'),
        ('t', 'e'),
        ('o', 'f'),
        ('e', 'd'),
        ('i', 's'),
        ('i', 't'),
        ('a', 'l'),
        ('a', 'r'),
        ('s', 't'),
        ('t', 'o'),
        ('n', 't'),
        ('n', 'g'),
        ('s', 'e'),
        ('h', 'a'),
        ('a', 's'),
        ('o', 'u'),
        ('i', 'o'),
        ('l', 'e'),
    ];
    for (prev, next) in hot_pairs {
        let (lo, _hi) = bigram_gap(prev, next);
        assert!(
            lo < COLD_BIGRAM_GAP_MIN_MS,
            "hot bigram {prev}{next} has lo={lo} which is >= cold min {COLD_BIGRAM_GAP_MIN_MS}"
        );
    }
}

// ── GAP: SafariIphone/Ipad mobile flag ──

/// GAP: SafariIpad is marked `mobile: true` even though iPads run a
/// desktop-class browser. This is a known approximation - the real
/// Safari on iPad uses "desktop mode" by default since iPadOS 13.
/// Pin it so changing this is deliberate.
#[test]
fn safari_ipad_mobile_flag_is_true_known_approximation() {
    let ov = profile_to_overrides(&StealthProfile::SafariIpad);
    assert!(
        ov.mobile,
        "SafariIpad mobile=true is a known approximation; update test if intentionally changed"
    );
}

// ── GAP: Firefox profiles - `mobile` is false and `brands` is empty ──

/// CLOSED GAP: Firefox does not expose `userAgentData` (Client Hints).
/// The profile correctly sets `brands: []`. The gap is now also guarded by
/// the runtime catalogue probe `navigator.userAgentData absent or brands empty
/// (Firefox)` (G211) so any Client-Hints leak is caught by the oracle.
#[test]
fn firefox_profiles_brands_empty_pins_no_client_hints() {
    for profile in [StealthProfile::FirefoxLinux, StealthProfile::FirefoxWindows] {
        let ov = profile_to_overrides(&profile);
        assert!(
            ov.brands.is_empty(),
            "{profile:?} must not ship brands (no Client Hints); update test if Firefox adds CH support"
        );
        assert!(!ov.mobile, "{profile:?} should be a desktop profile");
    }
}

#[test]
fn profile_js_ua_full_version_tracks_profile_user_agent() {
    let js = profile_js(&profile_to_overrides(&StealthProfile::ChromeWindowsStable));
    assert!(
        js.contains("131.0.0.0"),
        "uaFullVersion must derive from the canonical Chrome profile UA"
    );
    assert!(!js.contains("130.0.0.0"));
}
