use super::*;

#[test]
fn bundled_corpus_has_at_least_eight_traces() {
    // Less than this and the per-call sampler runs out of
    // diversity quickly - anti-bot ML can fingerprint 4-trace
    // corpora. 8 is the floor.
    assert!(bundled_corpus().len() >= 8);
}

#[test]
fn every_bundled_trace_terminates_at_unit_square() {
    for (i, t) in bundled_corpus().iter().enumerate() {
        let cumul = t.cumulative();
        let (x, y, _) = *cumul.last().unwrap();
        assert!(
            (x - 1.0).abs() < 1e-3,
            "trace #{i} ends at x={x}, expected 1.0"
        );
        assert!(
            (y - 1.0).abs() < 1e-3,
            "trace #{i} ends at y={y}, expected 1.0"
        );
    }
}

#[test]
fn every_bundled_trace_has_realistic_step_count() {
    // <8 steps = synthetic-bezier territory. >100 steps =
    // unrealistic 1000Hz sampling. Real corpora cluster
    // 10-50.
    for (i, t) in bundled_corpus().iter().enumerate() {
        assert!(
            (8..=100).contains(&t.steps.len()),
            "trace #{i} has {} steps (expect 8..=100)",
            t.steps.len()
        );
    }
}

#[test]
fn every_bundled_trace_has_realistic_inter_step_delay() {
    // Real pointing devices report at ~62-125 Hz (8-16 ms). We
    // allow up to 50ms for natural pause-and-think frames in
    // the long traces.
    for (i, t) in bundled_corpus().iter().enumerate() {
        for (j, s) in t.steps.iter().enumerate() {
            assert!(
                (5..=50).contains(&s.dt_ms),
                "trace #{i} step #{j} dt_ms = {} (expect 5..=50)",
                s.dt_ms
            );
        }
    }
}

#[test]
fn every_bundled_trace_has_natural_duration() {
    // Real-corpus durations span a wide range: fast deliberate
    // swipes can land at 100ms (8-12 step minimal-pause moves);
    // contemplative deliberation traces stretch to ~1500ms.
    // Bound 100..=1800 captures the realistic envelope. Below
    // 100ms is single-frame jitter dominated; above 1800ms is
    // outlier territory we shouldn't ship by default.
    for (i, t) in bundled_corpus().iter().enumerate() {
        let d = t.duration_ms();
        assert!(
            (100..=1800).contains(&d),
            "trace #{i} duration {d}ms (expect 100..=1800)"
        );
    }
}

#[test]
fn sampler_returns_a_trace_with_at_least_one_step() {
    let s = MouseSampler::new();
    let t = s.sample(100.0, 200.0, 400.0, 350.0);
    assert!(!t.steps.is_empty());
}

#[test]
fn sampler_lands_exactly_on_requested_end_coordinate() {
    let sampler = MouseSampler::new();
    // The last-step jitter compensation lands the cumulative end EXACTLY on the
    // requested (x1, y1) (f32 rounding aside), the documented guarantee. Before
    // the fix this drifted up to ~100px (random-walked jitter), which would miss a
    // click target.
    for _ in 0..50 {
        let t = sampler.sample(50.0, 50.0, 500.0, 400.0);
        let cumul = t.cumulative();
        let (end_x, end_y, _) = *cumul.last().unwrap();
        let actual_end_x = 50.0 + end_x;
        let actual_end_y = 50.0 + end_y;
        assert!(
            (actual_end_x - 500.0).abs() < 0.5,
            "end_x = {actual_end_x}, expected exactly 500 (drift not compensated?)"
        );
        assert!(
            (actual_end_y - 400.0).abs() < 0.5,
            "end_y = {actual_end_y}, expected exactly 400 (drift not compensated?)"
        );
    }
}

#[test]
fn resampled_path_lands_exactly_and_follows_real_curvature() {
    use rand::SeedableRng;
    let sampler = MouseSampler::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    let (x0, y0, x1, y1) = (120.0_f64, 90.0_f64, 640.0_f64, 480.0_f64);
    for _ in 0..50 {
        let path = sampler.resampled_path(x0, y0, x1, y1, 24, 3.0, &mut rng);
        assert_eq!(
            path.len(),
            24,
            "resampled_path must return exactly n_points"
        );
        // EXACT endpoints (the click driver lands precisely on the target).
        assert!(
            (path[0].0 - x0).abs() < 1e-9 && (path[0].1 - y0).abs() < 1e-9,
            "first point not (x0,y0)"
        );
        assert!(
            (path[23].0 - x1).abs() < 1e-9 && (path[23].1 - y1).abs() < 1e-9,
            "last point not (x1,y1)"
        );
        // All finite.
        for &(px, py) in &path {
            assert!(
                px.is_finite() && py.is_finite(),
                "non-finite point ({px},{py})"
            );
        }
        // Real curvature: at least one interior point deviates meaningfully from
        // the straight line start→end (a corpus trace, not a degenerate segment).
        let max_dev = path
            .iter()
            .map(|&(px, py)| {
                // perpendicular distance from the straight line (x0,y0)->(x1,y1)
                let dx = x1 - x0;
                let dy = y1 - y0;
                let len = (dx * dx + dy * dy).sqrt().max(1e-9);
                ((px - x0) * dy - (py - y0) * dx).abs() / len
            })
            .fold(0.0_f64, f64::max);
        assert!(
            max_dev > 2.0,
            "resampled path is essentially a straight line (max deviation {max_dev:.2}px). \
             not real-human curvature"
        );
    }
}

#[test]
fn resampled_path_handles_zero_length_move_without_panicking() {
    use rand::SeedableRng;
    let sampler = MouseSampler::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    // Same start/end (a no-op move) and a 2-point request must not panic or drift.
    let path = sampler.resampled_path(300.0, 300.0, 300.0, 300.0, 2, 2.0, &mut rng);
    assert_eq!(path.len(), 2);
    assert_eq!(path[0], (300.0, 300.0));
    assert_eq!(path[1], (300.0, 300.0));
}

#[test]
fn sampler_produces_distinct_paths_across_calls() {
    let sampler = MouseSampler::new();
    let a = sampler.sample(0.0, 0.0, 100.0, 100.0);
    let b = sampler.sample(0.0, 0.0, 100.0, 100.0);
    // Statistically should differ (random trace pick + jitter).
    // Equal coordinate sequences would mean either RNG is
    // broken or the corpus has only one trace.
    assert!(
        a.steps != b.steps,
        "two consecutive samples produced identical paths - sampler RNG broken?"
    );
}

#[test]
fn extra_traces_are_added_to_corpus() {
    let s = MouseSampler::new().with_extra_traces(vec![Trace {
        steps: vec![Step {
            dx: 1.0,
            dy: 1.0,
            dt_ms: 100,
        }],
    }]);
    assert!(s.corpus().len() >= 9);
}

#[test]
fn cumulative_starts_at_origin() {
    let t = Trace {
        steps: vec![Step {
            dx: 0.5,
            dy: 0.5,
            dt_ms: 100,
        }],
    };
    let cumul = t.cumulative();
    assert_eq!(cumul[0], (0.0, 0.0, 0));
}

#[test]
fn arc_length_sums_step_distances() {
    // 3-4-5 triangle steps → arc length = 5 + 5 = 10.
    let t = Trace {
        steps: vec![
            Step {
                dx: 3.0,
                dy: 4.0,
                dt_ms: 10,
            },
            Step {
                dx: -3.0,
                dy: -4.0,
                dt_ms: 10,
            },
        ],
    };
    assert!((t.arc_length() - 10.0).abs() < 1e-5);
}

#[test]
fn duration_ms_is_zero_for_empty_trace() {
    let t = Trace { steps: vec![] };
    assert_eq!(t.duration_ms(), 0);
}

// ── G132 / G134: statistical realism vs the bundled human corpus ───────────

/// Mean absolute curvature (radians per interior point) of a trace. Humans
/// produce smooth, curved paths; synthetic straight-line/bezier-only paths have
/// near-zero curvature.
fn mean_abs_curvature(trace: &Trace) -> f64 {
    let cumul: Vec<(f32, f32)> = trace
        .cumulative()
        .into_iter()
        .map(|(x, y, _)| (x, y))
        .collect();
    if cumul.len() < 3 {
        return 0.0;
    }
    let mut total = 0.0f64;
    let mut count = 0usize;
    for i in 1..cumul.len() - 1 {
        let (x0, y0) = cumul[i - 1];
        let (x1, y1) = cumul[i];
        let (x2, y2) = cumul[i + 1];
        let v1x = x1 - x0;
        let v1y = y1 - y0;
        let v2x = x2 - x1;
        let v2y = y2 - y1;
        let cross = (v1x * v2y - v1y * v2x) as f64;
        let dot = (v1x * v2x + v1y * v2y) as f64;
        let angle = cross.atan2(dot).abs();
        total += angle;
        count += 1;
    }
    if count == 0 {
        0.0
    } else {
        total / count as f64
    }
}

/// Mean absolute jerk (px/ms³, normalised units) of a trace. Human hand motion
/// has bounded, non-zero jerk; perfectly eased synthetic paths have near-zero
/// or unnaturally constant jerk.
fn mean_abs_jerk(trace: &Trace) -> f64 {
    let cumul = trace.cumulative();
    if cumul.len() < 4 {
        return 0.0;
    }
    let mut total = 0.0f64;
    let mut count = 0usize;
    for i in 2..cumul.len() - 1 {
        let dt1 = (cumul[i].2.saturating_sub(cumul[i - 1].2)).max(1) as f64;
        let dt2 = (cumul[i + 1].2.saturating_sub(cumul[i].2)).max(1) as f64;
        let vx1 = (cumul[i].0 - cumul[i - 1].0) as f64 / dt1;
        let vy1 = (cumul[i].1 - cumul[i - 1].1) as f64 / dt1;
        let vx2 = (cumul[i + 1].0 - cumul[i].0) as f64 / dt2;
        let vy2 = (cumul[i + 1].1 - cumul[i].1) as f64 / dt2;
        let ax1 = (vx1
            - (cumul[i - 1].0 - cumul[i - 2].0) as f64
                / (cumul[i - 1].2.saturating_sub(cumul[i - 2].2)).max(1) as f64)
            / dt1;
        let ay1 = (vy1
            - (cumul[i - 1].1 - cumul[i - 2].1) as f64
                / (cumul[i - 1].2.saturating_sub(cumul[i - 2].2)).max(1) as f64)
            / dt1;
        let ax2 = (vx2 - vx1) / dt2;
        let ay2 = (vy2 - vy1) / dt2;
        let jx = ax2 - ax1;
        let jy = ay2 - ay1;
        total += (jx * jx + jy * jy).sqrt();
        count += 1;
    }
    if count == 0 {
        0.0
    } else {
        total / count as f64
    }
}

/// Normalise a sampled trace back to the unit square so curvature/jerk are
/// comparable to the bundled corpus.
fn normalise_to_unit_square(trace: &Trace, start: (f32, f32), end: (f32, f32)) -> Trace {
    let dx = end.0 - start.0;
    let dy = end.1 - start.1;
    let scale_x = if dx.abs() < 1e-6 { 1.0 } else { 1.0 / dx };
    let scale_y = if dy.abs() < 1e-6 { 1.0 } else { 1.0 / dy };
    let steps = trace
        .steps
        .iter()
        .map(|s| Step {
            dx: s.dx * scale_x,
            dy: s.dy * scale_y,
            dt_ms: s.dt_ms,
        })
        .collect();
    Trace { steps }
}

#[test]
fn sampled_mouse_traces_match_corpus_curvature_and_jerk() {
    let sampler = MouseSampler::new();
    let corpus = bundled_corpus();
    let corpus_curvature: f64 =
        corpus.iter().map(mean_abs_curvature).sum::<f64>() / corpus.len().max(1) as f64;
    let corpus_jerk: f64 =
        corpus.iter().map(mean_abs_jerk).sum::<f64>() / corpus.len().max(1) as f64;

    // Affine transforms preserve curvature; normalising back to unit scale
    // makes jerk comparable to the corpus. The sampled population should track
    // the bundled human data on both metrics.
    let samples = 200;
    let (sample_curvature, sample_jerk): (f64, f64) = (0..samples)
        .map(|i| {
            let start = (0.0_f32, 0.0_f32);
            let end = (800.0_f32, (600.0 + (i % 50) as f32));
            let t = sampler.sample(start.0, start.1, end.0, end.1);
            let norm = normalise_to_unit_square(&t, start, end);
            (mean_abs_curvature(&norm), mean_abs_jerk(&norm))
        })
        .fold((0.0, 0.0), |(c, j), (dc, dj)| (c + dc, j + dj));
    let sample_curvature = sample_curvature / samples as f64;
    let sample_jerk = sample_jerk / samples as f64;

    // Curvature is measured in radians. The corpus mean is ~0.1–0.4 rad;
    // sampled traces should stay within 0.15 rad of the corpus mean.
    assert!(
        (sample_curvature - corpus_curvature).abs() < 0.15,
        "sampled curvature {sample_curvature:.4} drifted from corpus {corpus_curvature:.4}"
    );
    // Jerk units are arbitrary because traces are normalised; the important
    // property is non-zero, bounded jerk of the same order as the corpus.
    assert!(
        sample_jerk > 0.0 && (sample_jerk - corpus_jerk).abs() / corpus_jerk.max(1e-6) < 2.0,
        "sampled jerk {sample_jerk:.4} is not of the same order as corpus {corpus_jerk:.4}"
    );
}

#[test]
fn bundled_corpus_contains_micro_movements() {
    // G134: at least one bundled trace has small direction reversals (tremor)
    // characteristic of real hand motion.
    let mut reversals = 0usize;
    for trace in bundled_corpus() {
        let cumul: Vec<(f32, f32)> = trace
            .cumulative()
            .into_iter()
            .map(|(x, y, _)| (x, y))
            .collect();
        for i in 2..cumul.len() {
            let v1x = cumul[i - 1].0 - cumul[i - 2].0;
            let v1y = cumul[i - 1].1 - cumul[i - 2].1;
            let v2x = cumul[i].0 - cumul[i - 1].0;
            let v2y = cumul[i].1 - cumul[i - 1].1;
            let dot = v1x * v2x + v1y * v2y;
            if dot < 0.0 {
                reversals += 1;
            }
        }
    }
    assert!(
        reversals >= 3,
        "expected >= 3 direction reversals across corpus, found {reversals}"
    );
}

#[test]
fn bundled_corpus_contains_overshoot_correction() {
    // G134: trace #3 in the bundled corpus is explicitly an overshoot+correction
    // pattern. Its cumulative path should overshoot past (1,1) and then return.
    let corpus = bundled_corpus();
    let mut found = false;
    for trace in &corpus {
        let xs: Vec<f32> = trace.cumulative().iter().map(|(x, _, _)| *x).collect();
        let ys: Vec<f32> = trace.cumulative().iter().map(|(_, y, _)| *y).collect();
        if let Some(max_x) = xs
            .iter()
            .copied()
            .fold(None::<f32>, |a, b| a.map(|a: f32| a.max(b)).or(Some(b)))
        {
            if max_x >= 1.04 {
                found = true;
            }
        }
        if let Some(max_y) = ys
            .iter()
            .copied()
            .fold(None::<f32>, |a, b| a.map(|a: f32| a.max(b)).or(Some(b)))
        {
            if max_y >= 1.04 {
                found = true;
            }
        }
    }
    assert!(
        found,
        "no bundled trace overshoots past the target and corrects"
    );
}

#[test]
fn bundled_corpus_pause_distribution_has_variance() {
    // G134: real hand motion has a non-uniform pause distribution. The bundled
    // corpus must include short device-polling intervals and longer pauses.
    let mut all_dt: Vec<u32> = Vec::new();
    for trace in bundled_corpus() {
        for s in &trace.steps {
            all_dt.push(s.dt_ms);
        }
    }
    assert!(!all_dt.is_empty());
    let mean = all_dt.iter().sum::<u32>() as f64 / all_dt.len() as f64;
    let variance = all_dt
        .iter()
        .map(|v| {
            let d = *v as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / all_dt.len() as f64;
    let std = variance.sqrt();
    assert!(
        std > 3.0,
        "pause distribution std {std:.1} is too uniform; expected > 3 ms"
    );
    assert!(
        all_dt.iter().any(|dt| *dt >= 25),
        "expected at least one human pause >= 25 ms"
    );
}

#[test]
fn affine_transform_handles_zero_length_normalised_trace_gracefully() {
    // Edge case: a trace whose cumulative end is (0, 0) - the
    // transform must not divide by zero.
    let trace = Trace {
        steps: vec![
            Step {
                dx: 0.5,
                dy: 0.5,
                dt_ms: 10,
            },
            Step {
                dx: -0.5,
                dy: -0.5,
                dt_ms: 10,
            },
        ],
    };
    let mut rng = rand::rngs::StdRng::from_entropy_via_thread_local();
    let out = affine_transform_with_jitter(&trace, (0.0, 0.0), (100.0, 100.0), &mut rng);
    assert_eq!(out.steps.len(), 2);
}
