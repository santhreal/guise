//! G160 / Law 7, every public timing sampler stays inside a human-plausible
//! envelope for ALL inputs: never 0 / negative / superhuman-fast, never absurdly
//! long. The clamps are LOAD-BEARING: `estimate` floors WPM at 100 and clamps
//! the result to [500 ms, 120 s]; `jittered_step` has a 1 ms floor and clamps
//! `spread` to [0, 0.95]; the `SessionPacing` fatigue factor asymptotes strictly
//! below 1.5. This proves those guards hold under ADVERSARIAL configs/inputs
//! (degenerate WPM, empty/huge text, out-of-range spread, long sessions), not
//! just the happy path (so a future edit that drops a clamp fails here).
use super::*;
use proptest::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

const READING_FLOOR_MS: u128 = 500;
const READING_CEIL_MS: u128 = 120_000;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn reading_time_bounded_for_any_text_and_config(
        mean in 0.0f64..10_000.0,
        std in 0.0f64..10_000.0,
        word_count in 0usize..50_000,
    ) {
        let d = ReadingTimeEstimator::new(mean, std).estimate_words(word_count).as_millis();
        prop_assert!(
            d >= READING_FLOOR_MS,
            "reading time {d}ms below the 500ms floor (mean={mean}, std={std}, words={word_count})"
        );
        prop_assert!(d <= READING_CEIL_MS, "reading time {d}ms above the 120s ceiling");
    }

    #[test]
    fn jittered_step_never_zero_and_within_clamped_spread(
        nominal_ms in 0u64..600_000,
        spread in -5.0f64..5.0,            // out-of-range spreads MUST clamp
        seed in any::<u64>(),
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let out = jittered_step(Duration::from_millis(nominal_ms), spread, &mut rng).as_millis();
        prop_assert!(out >= 1, "jittered_step collapsed to a zero-delay burst");
        // spread is clamped to [0,0.95] → output never exceeds nominal·1.95 (+1 rounding).
        let ceil = ((nominal_ms as f64 * 1.95).round() as u128 + 1).max(1);
        prop_assert!(out <= ceil, "jittered_step {out}ms exceeded the clamped-spread ceiling {ceil}ms");
    }

    #[test]
    fn session_pacing_pauses_and_fatigue_bounded_over_a_long_session(seed in any::<u64>()) {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut pacing = SessionPacing::new();
        for _ in 0..1_000 {
            if let Some(d) = pacing.advance(&mut rng) {
                let ms = d.as_millis();
                prop_assert!(ms >= 1, "pacing produced a zero-length pause");
                // fatigue < 1.5, idle pause < 15s, burst < 3s → each pause < ~27s.
                prop_assert!(ms <= 30_000, "pacing pause {ms}ms exceeded the ~27s human ceiling");
            }
            let f = pacing.fatigue();
            prop_assert!((1.0..1.5).contains(&f), "fatigue {f} escaped [1.0, 1.5)");
        }
    }
}

#[test]
fn action_delays_stay_in_their_documented_ranges() {
    for _ in 0..5_000 {
        let bc = ActionDelay::before_click().as_millis();
        assert!(
            (200..=800).contains(&bc),
            "before_click {bc}ms out of 200-800"
        );
        let ff = ActionDelay::form_field_transition().as_millis();
        assert!(
            (300..=1_200).contains(&ff),
            "form_field_transition {ff}ms out of 300-1200"
        );
        let pl = ActionDelay::after_page_load().as_millis();
        assert!(
            (800..=3_000).contains(&pl),
            "after_page_load {pl}ms out of 800-3000"
        );
        let mc = ActionDelay::micro().as_millis();
        assert!((50..=200).contains(&mc), "micro {mc}ms out of 50-200");
    }
}
