use super::*;
use rand::SeedableRng;

#[test]
fn hot_bigrams_table_is_lowercase_and_two_chars() {
    for (k, _, _) in HOT_BIGRAMS {
        assert_eq!(k.len(), 2, "bigram key {} not 2 chars", k);
        assert_eq!(*k, k.to_lowercase(), "bigram key {} not lowercase", k);
    }
}

#[test]
fn bigram_gap_uses_hot_table_for_th() {
    let (lo, hi) = bigram_gap('t', 'h');
    assert_eq!(lo, 60);
    assert_eq!(hi, 100);
}

#[test]
fn bigram_gap_is_case_insensitive() {
    assert_eq!(bigram_gap('T', 'h'), bigram_gap('t', 'h'));
    assert_eq!(bigram_gap('t', 'H'), bigram_gap('t', 'h'));
    assert_eq!(bigram_gap('T', 'H'), bigram_gap('t', 'h'));
}

#[test]
fn bigram_gap_falls_back_to_cold_envelope() {
    assert_eq!(
        bigram_gap('q', 'z'),
        (COLD_BIGRAM_GAP_MIN_MS, COLD_BIGRAM_GAP_MAX_MS)
    );
    assert_eq!(
        bigram_gap('x', 'q'),
        (COLD_BIGRAM_GAP_MIN_MS, COLD_BIGRAM_GAP_MAX_MS)
    );
}

#[test]
fn space_transition_uses_space_envelope() {
    let (lo, hi) = bigram_gap('e', ' ');
    assert_eq!(lo, SPACE_GAP_MIN_MS);
    assert_eq!(hi, SPACE_GAP_MAX_MS);
}

#[test]
fn digit_pair_uses_digit_envelope() {
    let (lo, hi) = bigram_gap('5', '7');
    assert_eq!(lo, DIGIT_GAP_MIN_MS);
    assert_eq!(hi, DIGIT_GAP_MAX_MS);
}

#[test]
fn digit_to_letter_uses_cold_or_hot_table() {
    // Digit-to-letter is NOT a digit-pair; should fall through
    // to bigram lookup which (for "5a") will be cold.
    let (lo, hi) = bigram_gap('5', 'a');
    assert_eq!(lo, COLD_BIGRAM_GAP_MIN_MS);
    assert_eq!(hi, COLD_BIGRAM_GAP_MAX_MS);
}

#[test]
fn hold_envelope_matches_class_buckets() {
    let (lo, _) = hold_envelope('a');
    assert_eq!(lo, 30);
    let (lo_u, _) = hold_envelope('A');
    assert_eq!(lo_u, 50);
    let (lo_d, _) = hold_envelope('7');
    assert_eq!(lo_d, 45);
    let (lo_s, _) = hold_envelope(' ');
    assert_eq!(lo_s, 35);
}

#[test]
fn qwerty_neighbour_for_letters_returns_a_neighbour() {
    for ch in 'a'..='z' {
        let n = qwerty_neighbour(ch, 0);
        assert!(n.is_some(), "no neighbour table for {}", ch);
        let nch = n.unwrap();
        assert_ne!(nch, ch, "neighbour of {} is itself", ch);
    }
}

#[test]
fn qwerty_neighbour_for_non_letters_is_none() {
    assert!(qwerty_neighbour('5', 0).is_none());
    assert!(qwerty_neighbour('!', 0).is_none());
    assert!(qwerty_neighbour(' ', 0).is_none());
}

#[test]
fn plan_keystrokes_no_typos_no_pauses_preserves_length() {
    let mut rng = StdRng::seed_from_u64(1);
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("the quick", plan, &mut rng);
    assert_eq!(keys.len(), 9);
    assert!(keys.iter().all(|k| !k.is_correction));
}

#[test]
fn plan_keystrokes_with_typos_inserts_correction_pairs() {
    let mut rng = StdRng::seed_from_u64(42);
    let plan = TypingPlan {
        typo_probability: 1.0, // Every alpha char triggers a typo.
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("ab", plan, &mut rng);
    // 2 chars × (typo + backspace + real) = 6 keystrokes.
    assert_eq!(keys.len(), 6);
    assert!(keys[0].is_correction); // wrong char for 'a'
    assert_eq!(keys[1].ch, '\u{0008}'); // backspace
    assert!(keys[1].is_correction);
    assert!(!keys[2].is_correction); // real 'a'
    assert_eq!(keys[2].ch, 'a');
    assert!(keys[3].is_correction); // wrong char for 'b'
    assert_eq!(keys[4].ch, '\u{0008}');
    assert_eq!(keys[5].ch, 'b');
}

#[test]
fn plan_keystrokes_typos_skip_non_alpha() {
    let mut rng = StdRng::seed_from_u64(42);
    let plan = TypingPlan {
        typo_probability: 1.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("a 5 b", plan, &mut rng);
    // 'a' triggers (3), ' ' skipped (1), '5' skipped (1),
    // ' ' skipped (1), 'b' triggers (3) = 9.
    assert_eq!(keys.len(), 9);
}

#[test]
fn plan_keystrokes_thinking_pauses_extend_gaps() {
    let mut rng = StdRng::seed_from_u64(7);
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 1.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("the", plan, &mut rng);
    assert_eq!(keys.len(), 3);
    // First keystroke has no preceding context.
    assert_eq!(keys[0].gap_ms_before, 0);
    // Every subsequent keystroke gets a thinking pause of
    // ≥200ms ON TOP of the bigram baseline.
    for k in &keys[1..] {
        assert!(
            k.gap_ms_before >= 200,
            "expected thinking pause to extend gap to ≥200ms, got {}",
            k.gap_ms_before,
        );
    }
}

#[test]
fn plan_keystrokes_hot_bigrams_produce_fast_gaps() {
    let mut rng = StdRng::seed_from_u64(1234);
    let plan = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("the", plan, &mut rng);
    // 't' is the first keystroke - no preceding gap.
    assert_eq!(keys[0].gap_ms_before, 0);
    // 'h' carries the t→h bigram gap (60–100ms).
    assert!(
        keys[1].gap_ms_before >= 60 && keys[1].gap_ms_before <= 100,
        "t→h bigram should give 60–100ms, got {}",
        keys[1].gap_ms_before,
    );
    // 'e' carries the h→e bigram gap (65–105ms).
    assert!(
        keys[2].gap_ms_before >= 65 && keys[2].gap_ms_before <= 105,
        "h→e bigram should give 65–105ms, got {}",
        keys[2].gap_ms_before,
    );
}

#[test]
fn center_weighted_peaks_at_envelope_center_not_flat() {
    // The realised timing distribution must be unimodal within [lo, hi], not the
    // flat box a uniform `gen_range` produces (hard edges + equal density at the
    // rare extremes = a keystroke-dynamics distribution-shape tell). A symmetric
    // triangular draw puts ~56% of its mass in the central third of the envelope;
    // a uniform draw puts ~33%. Assert well above the uniform expectation so a
    // regression back to `gen_range(lo..=hi)` fails this with teeth.
    let mut rng = StdRng::seed_from_u64(7);
    let (lo, hi) = (180u16, 320u16); // the cold-bigram envelope, width 140.
    let third = (hi - lo) / 3;
    let (mid_lo, mid_hi) = (lo + third, hi - third);
    let n = 40_000usize;
    let mut middle = 0usize;
    for _ in 0..n {
        let v = center_weighted(&mut rng, lo, hi);
        assert!(v >= lo && v <= hi, "sample {v} escaped [{lo},{hi}]");
        if v >= mid_lo && v <= mid_hi {
            middle += 1;
        }
    }
    let middle_frac = middle as f64 / n as f64;
    assert!(
        middle_frac > 0.45,
        "central-third mass {middle_frac:.3} ≈ uniform (0.33), the sampler is flat, \
         not center-weighted; a real typist's per-bigram latency is unimodal"
    );
    // Degenerate envelope returns the single value, never panics on an empty range.
    assert_eq!(center_weighted(&mut rng, 90, 90), 90);
}

#[test]
fn plan_keystrokes_first_keystroke_has_zero_gap() {
    let mut rng = StdRng::seed_from_u64(0);
    let plan = TypingPlan::default();
    let keys = plan_keystrokes("a", plan, &mut rng);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].gap_ms_before, 0);
}

#[test]
fn plan_keystrokes_post_backspace_recovery_within_envelope() {
    let mut rng = StdRng::seed_from_u64(99);
    let plan = TypingPlan {
        typo_probability: 1.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let keys = plan_keystrokes("a", plan, &mut rng);
    // Sequence: [wrong-neighbour (correction), BS (correction), 'a' (real)].
    assert_eq!(keys.len(), 3);
    // The recovery gap on the real 'a' after the backspace must
    // be in the post-backspace envelope (60–180ms), NOT the
    // bigram envelope.
    assert!(
        keys[2].gap_ms_before >= 60 && keys[2].gap_ms_before <= 180,
        "post-backspace recovery should be 60–180ms, got {}",
        keys[2].gap_ms_before,
    );
}

// ── L4 behavioural-realism: generated rhythm must clear the human CV floor ──
//
// The probe layer (`probe::redteam::classify_timing_cv`) fails a *live browser*
// whose busy-loop timing CV drops below `HUMAN_TIMING_CV_FLOOR`: a near-uniform
// cadence is a sandbox/automation tell. These tests close the loop on the OTHER
// side: the keystroke rhythm guise itself *generates* must clear that very floor,
// for every seed, or the disguise would be flagged by the same metric (and any
// peer behavioural classifier). Detector threshold and generator output are bound
// to one constant in `crate::sampling`, so they can never silently drift apart.

#[test]
fn generated_typing_rhythm_clears_human_cv_floor() {
    use crate::sampling::{coefficient_of_variation, HUMAN_TIMING_CV_FLOOR};

    // A realistic sentence: hot bigrams, word boundaries, digits, a cold cluster.
    let text = "the quick brown fox jumps over 7 lazy dogs while typing fairly naturally";
    let plan = TypingPlan::default();

    // The property must hold for EVERY seed, not a lucky one (sweep a fleet).
    let mut worst = f64::INFINITY;
    let mut worst_seed = 0u64;
    for seed in 0..64u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let keys = plan_keystrokes(text, plan, &mut rng);
        // Inter-key gaps; the first keystroke is 0 by contract, so skip it.
        let gaps: Vec<f64> = keys
            .iter()
            .skip(1)
            .map(|k| k.gap_ms_before as f64)
            .collect();
        let cv = coefficient_of_variation(&gaps).expect("multi-key sample has a CV");
        if cv < worst {
            worst = cv;
            worst_seed = seed;
        }
    }
    assert!(
        worst >= HUMAN_TIMING_CV_FLOOR,
        "generated typing CV {worst:.4} (seed {worst_seed}) < human floor \
         {HUMAN_TIMING_CV_FLOOR}, the emitted rhythm is too uniform; the same \
         metric our probe gates a browser on would flag this disguise"
    );
}

#[test]
fn typo_and_pause_injection_widen_dispersion() {
    use crate::sampling::coefficient_of_variation;

    // Disabling typos and thinking pauses leaves only the bigram-envelope spread;
    // enabling them must not *reduce* dispersion (corrections/pauses add spikes).
    let text = "the quick brown fox jumps over the lazy dog";
    let bare = TypingPlan {
        typo_probability: 0.0,
        thinking_pause_probability: 0.0,
        ..Default::default()
    };
    let rich = TypingPlan::default();

    let cv_of = |plan: TypingPlan, seed: u64| {
        let mut rng = StdRng::seed_from_u64(seed);
        let keys = plan_keystrokes(text, plan, &mut rng);
        let gaps: Vec<f64> = keys
            .iter()
            .skip(1)
            .map(|k| k.gap_ms_before as f64)
            .collect();
        coefficient_of_variation(&gaps).expect("multi-key sample has a CV")
    };

    // Even the bare bigram-only rhythm should already clear the floor, the table
    // itself spans ~60–320ms, which is human-shaped dispersion on its own.
    let bare_cv = cv_of(bare, 1);
    assert!(
        bare_cv >= crate::sampling::HUMAN_TIMING_CV_FLOOR,
        "bare bigram rhythm CV {bare_cv:.4} should already be human-shaped"
    );

    // Averaged over seeds, the rich plan's dispersion is at least the bare one's.
    let mean_bare: f64 = (0..32).map(|s| cv_of(bare, s)).sum::<f64>() / 32.0;
    let mean_rich: f64 = (0..32).map(|s| cv_of(rich, s)).sum::<f64>() / 32.0;
    assert!(
        mean_rich >= mean_bare - 0.02,
        "rich plan dispersion {mean_rich:.4} collapsed below bare {mean_bare:.4}"
    );
}
