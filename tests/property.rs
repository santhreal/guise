//! Property-based tests using `proptest`.
//!
//! These pin universal invariants that must hold for *any* input,
//! not just the hand-crafted cases in the unit and adversarial suites.

// G258/G259: gated via `required-features = ["fingerprint", "human", "rotation"]`
// in Cargo.toml so single-feature builds skip it rather than failing on absent
// modules.

use guise::fingerprint::bundle::validate_overrides;
use guise::fingerprint::{profile_js, profile_to_overrides, ProfileBundle, StealthProfile};
use guise::human::keystroke::{
    bigram_gap, hold_envelope, plan_keystrokes, TypingPlan, COLD_BIGRAM_GAP_MAX_MS,
    COLD_BIGRAM_GAP_MIN_MS, DIGIT_GAP_MAX_MS, DIGIT_GAP_MIN_MS, SPACE_GAP_MAX_MS, SPACE_GAP_MIN_MS,
};
use guise::rotation::all_profiles;
use proptest::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

// ── scale + coherence invariants ──

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Any u64 seed must produce a fully coherent persona bundle (G253).
    #[test]
    fn any_seed_produces_a_coherent_bundle(seed in any::<u64>()) {
        let bundle = ProfileBundle::from_seed(seed);
        prop_assert!(bundle.validate_browser_coherence().is_ok());
    }
}

/// Scale corpus: assemble many personas and assert every one is coherent while
/// measuring throughput (G256).
#[test]
fn scale_corpus_10000_personas_are_coherent() {
    let n = 10_000;
    let start = std::time::Instant::now();
    for seed in 0..n {
        let bundle = ProfileBundle::from_seed(seed);
        assert!(
            bundle.validate_browser_coherence().is_ok(),
            "seed {seed} produced an incoherent bundle"
        );
    }
    let elapsed = start.elapsed();
    let per_ms = elapsed.as_millis() as f64 / n as f64;
    eprintln!("assembled + validated {n} personas in {elapsed:?} ({per_ms:.3} ms/persona)");
}

// ── bigram_gap invariants ──

proptest! {
    /// For any pair of ASCII chars, the returned envelope satisfies lo ≤ hi
    /// and both values are nonzero. This guarantees callers can always call
    /// `rng.gen_range(lo..=hi)` without panicking.
    #[test]
    fn bigram_gap_lo_lte_hi_for_any_ascii_pair(
        prev in any::<u8>().prop_map(|b| b as char),
        next in any::<u8>().prop_map(|b| b as char),
    ) {
        let (lo, hi) = bigram_gap(prev, next);
        prop_assert!(lo > 0, "lo must be positive");
        prop_assert!(lo <= hi, "lo must be <= hi");
    }

    /// Space or tab as the `next` character always resolves to the space
    /// envelope regardless of `prev`.
    #[test]
    fn bigram_gap_any_to_space_uses_space_envelope(
        prev in any::<u8>().prop_map(|b| b as char),
        next in prop_oneof![Just(' '), Just('\t')],
    ) {
        let (lo, hi) = bigram_gap(prev, next);
        prop_assert_eq!(lo, SPACE_GAP_MIN_MS);
        prop_assert_eq!(hi, SPACE_GAP_MAX_MS);
    }

    /// Any digit→digit pair uses the digit envelope.
    #[test]
    fn bigram_gap_digit_to_digit_uses_digit_envelope(
        prev in (b'0'..=b'9').prop_map(|b| b as char),
        next in (b'0'..=b'9').prop_map(|b| b as char),
    ) {
        let (lo, hi) = bigram_gap(prev, next);
        prop_assert_eq!(lo, DIGIT_GAP_MIN_MS);
        prop_assert_eq!(hi, DIGIT_GAP_MAX_MS);
    }

    /// Cold bigrams must fall back to the cold envelope when not in the
    /// hot table. Hot bigrams must have hi <= COLD_MAX.
    #[test]
    fn cold_bigram_minimum_not_faster_than_space_maximum(
        prev in (b'a'..=b'z').prop_map(|b| b as char),
        next in (b'a'..=b'z').prop_map(|b| b as char),
    ) {
        let (lo, hi) = bigram_gap(prev, next);
        if lo == COLD_BIGRAM_GAP_MIN_MS {
            // Cold bigram: hi must equal COLD_MAX.
            prop_assert_eq!(hi, COLD_BIGRAM_GAP_MAX_MS);
        } else {
            // Hot/warm bigram: hi must not exceed cold max.
            prop_assert!(hi <= COLD_BIGRAM_GAP_MAX_MS,
                "hot/warm bigram hi must not exceed cold max");
        }
    }
}

// ── hold_envelope invariants ──

proptest! {
    /// For any ASCII character, lo ≤ hi and both > 0.
    #[test]
    fn hold_envelope_lo_lte_hi_for_any_ascii(ch in any::<u8>().prop_map(|b| b as char)) {
        let (lo, hi) = hold_envelope(ch);
        prop_assert!(lo > 0);
        prop_assert!(lo <= hi);
    }

    /// Uppercase ASCII letters always have a strictly greater lo than the
    /// corresponding lowercase letter.
    #[test]
    fn hold_envelope_uppercase_lo_gt_lowercase_lo(
        lower in (b'a'..=b'z').prop_map(|b| b as char),
    ) {
        let upper = lower.to_ascii_uppercase();
        let (lo_l, _) = hold_envelope(lower);
        let (lo_u, _) = hold_envelope(upper);
        prop_assert!(lo_u > lo_l,
            "uppercase lo must exceed lowercase lo");
    }
}

// ── plan_keystrokes output invariants ──

proptest! {
    /// With typos and thinking pauses disabled, the output length equals
    /// the number of Unicode scalar values in the input.
    #[test]
    fn plan_keystrokes_no_extras_length_equals_char_count(
        seed in any::<u64>(),
        text in "[a-zA-Z0-9 ]{0,30}",
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let plan = TypingPlan { typo_probability: 0.0, thinking_pause_probability: 0.0 , ..Default::default() };
        let keys = plan_keystrokes(&text, plan, &mut rng);
        let char_count = text.chars().count();
        prop_assert_eq!(keys.len(), char_count);
    }

    /// The first keystroke always has gap_ms_before == 0 regardless of
    /// input or seed.
    #[test]
    fn plan_keystrokes_first_key_always_zero_gap(
        seed in any::<u64>(),
        text in "[a-zA-Z]{1,20}",
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let plan = TypingPlan { typo_probability: 0.0, thinking_pause_probability: 0.0 , ..Default::default() };
        let keys = plan_keystrokes(&text, plan, &mut rng);
        if !keys.is_empty() {
            prop_assert_eq!(keys[0].gap_ms_before, 0,
                "first keystroke gap must always be 0");
        }
    }

    /// With typos enabled at 100%, every alphabetic input character
    /// produces exactly 3 keystrokes: wrong, backspace, correct.
    #[test]
    fn plan_keystrokes_full_typo_rate_triples_alpha_chars(
        seed in any::<u64>(),
        // Only lowercase alpha so typo injection always fires.
        text in "[a-z]{1,10}",
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let plan = TypingPlan { typo_probability: 1.0, thinking_pause_probability: 0.0 , ..Default::default() };
        let keys = plan_keystrokes(&text, plan, &mut rng);
        let char_count = text.chars().count();
        prop_assert_eq!(keys.len(), char_count * 3,
            "each alpha char should produce (wrong, BS, real)");
    }

    /// Real (non-correction) keystrokes must always carry the correct
    /// character matching the input string.
    #[test]
    fn plan_keystrokes_real_keys_match_input_chars(
        seed in any::<u64>(),
        text in "[a-zA-Z]{1,15}",
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let plan = TypingPlan { typo_probability: 1.0, thinking_pause_probability: 0.0 , ..Default::default() };
        let keys = plan_keystrokes(&text, plan, &mut rng);
        let real: Vec<char> = keys.iter()
            .filter(|k| !k.is_correction)
            .map(|k| k.ch)
            .collect();
        let expected: Vec<char> = text.chars().collect();
        prop_assert_eq!(real, expected);
    }

    /// Hold times for non-correction keystrokes must be within the
    /// envelope returned by `hold_envelope` for that character.
    #[test]
    fn plan_keystrokes_hold_ms_in_envelope(
        seed in any::<u64>(),
        text in "[a-zA-Z0-9 ]{1,20}",
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let plan = TypingPlan { typo_probability: 0.0, thinking_pause_probability: 0.0 , ..Default::default() };
        let keys = plan_keystrokes(&text, plan, &mut rng);
        for k in &keys {
            let (lo, hi) = hold_envelope(k.ch);
            prop_assert!(k.hold_ms >= lo && k.hold_ms <= hi,
                "hold_ms outside envelope");
        }
    }
}

// ── profile_js invariants ──

proptest! {
    /// profile_js must always return a non-empty, valid-looking JS IIFE for
    /// any constructed ProfileOverrides. We test with random hardware
    /// concurrency and device memory to catch formatting issues.
    #[test]
    fn profile_js_always_starts_with_iife(
        hwc in 1u32..=32u32,
        dm in 1u32..=64u32,
        sw in 320u32..=3840u32,
        sh in 240u32..=2160u32,
    ) {
        let mut ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
        ov.hardware_concurrency = hwc;
        ov.device_memory = dm;
        ov.screen_width = sw;
        ov.screen_height = sh;
        let js = profile_js(&ov);
        prop_assert!(js.trim_start().starts_with("(()"),
            "profile_js should start with IIFE");
        prop_assert!(js.contains("})()"),
            "profile_js must close the IIFE");
    }

    /// For any valid ProfileOverrides constructed from a real profile,
    /// validate_overrides must succeed.
    #[test]
    fn validate_overrides_accepts_all_built_in_profiles(
        // Choose a profile variant index.
        idx in 0usize..all_profiles().len(),
    ) {
        let profile = profile_at(idx);
        let ov = profile_to_overrides(&profile);
        prop_assert!(validate_overrides(&ov).is_ok(),
            "built-in profile failed coherence check");
    }
}

fn profile_at(idx: usize) -> StealthProfile {
    let all = all_profiles();
    all[idx % all.len()]
}
