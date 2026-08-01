use super::*;
use rand::{rngs::StdRng, SeedableRng};
use std::time::Duration;

// ── ReadingTimeEstimator ─────────────────────────────────────────────

#[test]
fn reading_time_minimum_500ms() {
    let est = ReadingTimeEstimator::default();
    // Single word should still give >= 500 ms.
    let d = est.estimate("hello");
    assert!(
        d >= Duration::from_millis(500),
        "expected >= 500 ms, got {d:?}"
    );
}

#[test]
fn reading_time_grows_with_word_count() {
    let est = ReadingTimeEstimator::default();
    let short: u128 = (0..50).map(|_| est.estimate_words(10).as_millis()).sum();
    let long: u128 = (0..50).map(|_| est.estimate_words(100).as_millis()).sum();
    assert!(
        long > short,
        "long text ({long}) should take longer than short ({short})"
    );
}

#[test]
fn reading_time_under_120s() {
    let est = ReadingTimeEstimator::default();
    for _ in 0..50 {
        let d = est.estimate_words(500);
        assert!(
            d <= Duration::from_secs(120),
            "expected <= 120 s, got {d:?}"
        );
    }
}

// ── jittered_step ────────────────────────────────────────────────────

#[test]
fn jittered_step_breaks_the_constant_cadence() {
    // The whole point: a loop that sleeps `jittered_step(step)` must NOT tick
    // at a uniform interval, or it's the robotic timing tell G143 targets.
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let nominal = Duration::from_millis(40);
    let samples: Vec<u128> = (0..64)
        .map(|_| jittered_step(nominal, 0.30, &mut rng).as_millis())
        .collect();
    let first = samples[0];
    assert!(
        samples.iter().any(|&s| s != first),
        "jittered cadence collapsed to a constant {first}ms tick: {samples:?}"
    );
}

#[test]
fn jittered_step_stays_within_the_spread_band_and_above_the_floor() {
    let mut rng = StdRng::seed_from_u64(7);
    let nominal_ms = 50u128;
    let nominal = Duration::from_millis(nominal_ms as u64);
    for _ in 0..10_000 {
        let ms = jittered_step(nominal, 0.30, &mut rng).as_millis();
        // [50·0.7, 50·1.3] = [35, 65], rounded.
        assert!(
            (35..=65).contains(&ms),
            "{ms}ms escaped the ±30% band around {nominal_ms}ms"
        );
        assert!(ms >= 1, "step collapsed to a zero-delay burst");
    }
}

#[test]
fn jittered_step_mean_tracks_the_nominal() {
    // Symmetric jitter must not bias the cadence faster or slower on average.
    let mut rng = StdRng::seed_from_u64(99);
    let nominal_ms = 80.0;
    let nominal = Duration::from_millis(nominal_ms as u64);
    let n = 20_000;
    let total: u128 = (0..n)
        .map(|_| jittered_step(nominal, 0.30, &mut rng).as_millis())
        .sum();
    let mean = total as f64 / n as f64;
    assert!(
        (mean - nominal_ms).abs() < nominal_ms * 0.03,
        "mean cadence {mean:.1}ms drifted from nominal {nominal_ms}ms"
    );
}

#[test]
fn jittered_step_zero_spread_returns_the_nominal_and_never_zero() {
    let mut rng = StdRng::seed_from_u64(1);
    assert_eq!(
        jittered_step(Duration::from_millis(25), 0.0, &mut rng),
        Duration::from_millis(25)
    );
    // A sub-millisecond / zero nominal still yields a non-zero, non-bursting step.
    assert_eq!(
        jittered_step(Duration::from_millis(0), 0.5, &mut rng),
        Duration::from_millis(1)
    );
}

#[test]
fn reading_time_reasonable_for_200_words() {
    // At 225 WPM, 200 words ≈ 53 s; allow 30–90 s window.
    let est = ReadingTimeEstimator::default();
    let samples: Vec<Duration> = (0..100).map(|_| est.estimate_words(200)).collect();
    let mean_ms: u128 = samples.iter().map(|d| d.as_millis()).sum::<u128>() / 100;
    assert!(
        (30_000..=90_000).contains(&mean_ms),
        "mean {mean_ms} ms out of expected 30–90 s window"
    );
}

#[test]
fn empty_text_returns_minimum() {
    let est = ReadingTimeEstimator::default();
    let d = est.estimate("");
    assert_eq!(d, Duration::from_millis(500));
}

// ── ActionDelay ──────────────────────────────────────────────────────

#[test]
fn before_click_in_range() {
    for _ in 0..100 {
        let d = ActionDelay::before_click();
        assert!(
            d >= Duration::from_millis(200) && d <= Duration::from_millis(800),
            "before_click {d:?} out of 200–800 ms range"
        );
    }
}

#[test]
fn form_field_transition_in_range() {
    for _ in 0..100 {
        let d = ActionDelay::form_field_transition();
        assert!(
            d >= Duration::from_millis(300) && d <= Duration::from_millis(1_200),
            "form_field_transition {d:?} out of 300–1200 ms range"
        );
    }
}

#[test]
fn after_page_load_in_range() {
    for _ in 0..100 {
        let d = ActionDelay::after_page_load();
        assert!(
            d >= Duration::from_millis(800) && d <= Duration::from_millis(3_000),
            "after_page_load {d:?} out of 800–3000 ms range"
        );
    }
}

#[test]
fn micro_delay_in_range() {
    for _ in 0..100 {
        let d = ActionDelay::micro();
        assert!(
            d >= Duration::from_millis(50) && d <= Duration::from_millis(200),
            "micro delay {d:?} out of 50–200 ms range"
        );
    }
}

#[test]
fn hover_dwell_in_range() {
    for _ in 0..100 {
        let d = ActionDelay::hover_dwell();
        assert!(
            d >= Duration::from_millis(200) && d <= Duration::from_millis(700),
            "hover_dwell {d:?} out of 200–700 ms range"
        );
    }
}

#[test]
fn idle_pause_in_range() {
    for _ in 0..100 {
        let d = ActionDelay::idle();
        assert!(
            d >= Duration::from_millis(500) && d <= Duration::from_millis(2_000),
            "idle {d:?} out of 500–2000 ms range"
        );
    }
}

#[test]
fn between_actions_in_range() {
    for _ in 0..100 {
        let d = ActionDelay::between_actions();
        assert!(
            d >= Duration::from_millis(100) && d <= Duration::from_millis(400),
            "between_actions {d:?} out of 100–400 ms range"
        );
    }
}

#[test]
fn action_delays_are_not_fixed_sleeps() {
    // G230 / Law 7: every behavioral delay must be sampled from a distribution.
    // A fixed sleep would produce identical values.
    let mut distinct = std::collections::HashSet::new();
    for _ in 0..100 {
        distinct.insert(ActionDelay::before_click());
        distinct.insert(ActionDelay::between_actions());
        distinct.insert(ActionDelay::micro());
    }
    assert!(
        distinct.len() > 50,
        "behavioral delays collapsed to only {} distinct values",
        distinct.len()
    );
}

#[test]
fn uniform_respects_bounds() {
    for _ in 0..100 {
        let d = ActionDelay::uniform(150, 600);
        assert!(
            d >= Duration::from_millis(150) && d <= Duration::from_millis(600),
            "uniform {d:?} out of 150–600 ms range"
        );
    }
}

#[test]
#[should_panic(expected = "ActionDelay::uniform: min_ms")]
fn uniform_panics_when_min_exceeds_max() {
    let _ = ActionDelay::uniform(200, 100);
}

// ── SessionPacing ────────────────────────────────────────────────────

#[test]
fn initial_fatigue_is_one() {
    let pacing = SessionPacing::new();
    assert!((pacing.fatigue() - 1.0).abs() < 0.01);
}

#[test]
fn fatigue_increases_with_actions() {
    let mut pacing = SessionPacing::new();
    let mut rng = StdRng::seed_from_u64(11);
    for _ in 0..30 {
        pacing.advance(&mut rng);
    }
    assert!(
        pacing.fatigue() > 1.0,
        "fatigue should grow above 1.0 after 30 actions"
    );
}

#[test]
fn fatigue_stays_below_1_5() {
    let mut pacing = SessionPacing::new();
    let mut rng = StdRng::seed_from_u64(3);
    for _ in 0..500 {
        pacing.advance(&mut rng);
    }
    assert!(
        pacing.fatigue() < 1.5,
        "fatigue should stay below 1.5, got {}",
        pacing.fatigue()
    );
}

#[test]
fn advance_emits_burst_end_pause() {
    // With burst_remaining forced to 0, the next advance must return a pause.
    let mut pacing = SessionPacing::new();
    pacing.burst_remaining = 0;
    pacing.next_idle_at = u32::MAX; // suppress the idle branch
    let mut rng = StdRng::seed_from_u64(99);
    let pause = pacing.advance(&mut rng).expect("burst-end pause expected");
    // 800–3000 ms scaled by ~1.0 fatigue → comfortably in this window.
    assert!(
        pause >= Duration::from_millis(700) && pause <= Duration::from_millis(5_000),
        "burst pause {pause:?} out of expected window"
    );
    // A fresh burst was started.
    assert!(pacing.burst_remaining >= 3);
}

#[test]
fn advance_no_pause_mid_burst() {
    let mut pacing = SessionPacing::new();
    pacing.burst_remaining = 5;
    pacing.next_idle_at = u32::MAX;
    let mut rng = StdRng::seed_from_u64(7);
    assert!(
        pacing.advance(&mut rng).is_none(),
        "mid-burst tick should not pause"
    );
    assert_eq!(pacing.burst_remaining, 4);
}

#[test]
fn advance_idle_break_resets_counter() {
    let mut pacing = SessionPacing::new();
    pacing.burst_remaining = 5; // avoid the burst branch
    pacing.actions_taken = 0;
    pacing.next_idle_at = 1; // force idle on first advance
    let mut rng = StdRng::seed_from_u64(42);
    let pause = pacing.advance(&mut rng).expect("idle pause expected");
    assert!(
        pause >= Duration::from_millis(5_000),
        "idle pause too short: {pause:?}"
    );
    assert_eq!(
        pacing.actions_taken, 0,
        "idle break should reset the counter"
    );
}

#[test]
fn challenge_mode_doubles_pauses() {
    let mut pacing = SessionPacing::new();
    pacing.burst_remaining = 0;
    pacing.next_idle_at = u32::MAX;
    let mut rng = StdRng::seed_from_u64(5);
    let normal = pacing.advance(&mut rng).expect("burst pause");

    pacing.burst_remaining = 0;
    pacing.next_idle_at = u32::MAX;
    pacing.enter_challenge_mode();
    let mut rng = StdRng::seed_from_u64(5);
    let challenged = pacing.advance(&mut rng).expect("challenge pause");

    assert!(
        challenged >= normal,
        "challenge mode pause {challenged:?} should be >= normal {normal:?}"
    );
    assert!(
        challenged.as_millis() >= normal.as_millis().saturating_mul(2).saturating_sub(2),
        "challenge pause should be roughly double the normal pause"
    );
    assert!(pacing.is_challenge_mode());
    pacing.exit_challenge_mode();
    assert!(!pacing.is_challenge_mode());
}

#[test]
fn scale_duration_with_fatigue() {
    let mut pacing = SessionPacing::new();
    // Force fatigue to 1.2.
    pacing.fatigue = 1.2;
    let base = Duration::from_millis(1000);
    let scaled = pacing.scale_duration(base);
    assert!(
        scaled >= Duration::from_millis(1190) && scaled <= Duration::from_millis(1210),
        "scaled {scaled:?} should be ~1200 ms"
    );
}

#[test]
fn count_words_basic() {
    assert_eq!(count_words("hello world foo"), 3);
    assert_eq!(count_words(""), 0);
    assert_eq!(count_words("  spaces  "), 1);
}

#[test]
fn sample_normal_mean_near_zero() {
    let mut rng = StdRng::seed_from_u64(123);
    let n = 2000;
    let mean: f64 = (0..n).map(|_| standard_normal(&mut rng)).sum::<f64>() / n as f64;
    assert!(mean.abs() < 0.1, "normal mean {mean:.4} should be near 0");
}
