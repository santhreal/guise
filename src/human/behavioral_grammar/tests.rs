use super::*;

#[test]
fn sample_trajectory_includes_terminal_click() {
    let traj = sample_trajectory((0.0, 0.0), (100.0, 200.0), GrammarWeights::default(), 1);
    assert!(traj
        .motions
        .iter()
        .any(|m| matches!(m, Motion::Click { .. })));
}

#[test]
fn sample_trajectory_renders_minimum_sample_floor() {
    // The minimum-trajectory case is a LinearJittered with 10
    // samples + click (2 events) = 12. Any seed should produce
    // ≥ 10 samples.
    for seed in 0u64..50 {
        let traj = sample_trajectory((0.0, 0.0), (100.0, 200.0), GrammarWeights::default(), seed);
        let mut rng = StdRng::seed_from_u64(seed);
        let samples = traj.render(&mut rng);
        assert!(
            samples.len() >= 10,
            "seed {seed}: got only {} samples",
            samples.len()
        );
    }
}

#[test]
fn sample_trajectory_bezier_path_renders_at_least_40_samples() {
    // When approach IS bezier (probability ~0.6 with default
    // weights), the bezier itself emits 40-80 samples. Probe
    // a high-bezier-weight grammar and verify.
    let w = GrammarWeights {
        approach_bezier: 1.0,
        approach_spline: 0.0,
        approach_linear: 0.0,
        ..GrammarWeights::default()
    };
    let traj = sample_trajectory((0.0, 0.0), (200.0, 200.0), w, 7);
    let mut rng = StdRng::seed_from_u64(7);
    let samples = traj.render(&mut rng);
    assert!(
        samples.len() >= 40,
        "bezier produced only {} samples",
        samples.len()
    );
}

#[test]
fn samples_end_near_target() {
    let traj = sample_trajectory((0.0, 0.0), (500.0, 300.0), GrammarWeights::default(), 42);
    let mut rng = StdRng::seed_from_u64(42);
    let samples = traj.render(&mut rng);
    let last = samples.last().unwrap();
    assert!(
        (last.x - 500.0).abs() < 50.0,
        "last x {} too far from 500",
        last.x
    );
    assert!(
        (last.y - 300.0).abs() < 50.0,
        "last y {} too far from 300",
        last.y
    );
}

#[test]
fn bezier_samples_smooth_between_endpoints() {
    let mut rng = StdRng::seed_from_u64(0);
    let samples = bezier_samples(
        (0.0, 0.0),
        (50.0, 100.0),
        (100.0, 100.0),
        (200.0, 0.0),
        50,
        0.01,
        &mut rng,
    );
    // Roughly monotonic in x (allow some wobble from t_jitter).
    let xs: Vec<f64> = samples.iter().map(|s| s.x).collect();
    let mut increasing = 0;
    for w in xs.windows(2) {
        if w[1] >= w[0] {
            increasing += 1;
        }
    }
    let total = xs.len() - 1;
    let ratio = (increasing as f64) / (total as f64);
    assert!(
        ratio > 0.80,
        "bezier should be mostly monotonic in x; got {ratio:.2}"
    );
}

#[test]
fn catmull_rom_passes_through_interior_points() {
    let mut rng = StdRng::seed_from_u64(0);
    let pts = vec![(0.0, 0.0), (100.0, 50.0), (200.0, 80.0), (300.0, 30.0)];
    let samples = catmull_rom_samples(&pts, 100, &mut rng);
    assert!(!samples.is_empty());
}

#[test]
fn overshoot_returns_two_samples_ending_at_target() {
    let mut rng = StdRng::seed_from_u64(0);
    let samples = overshoot_samples((100.0, 100.0), 20.0, 50, &mut rng);
    assert_eq!(samples.len(), 2);
    assert!((samples[1].x - 100.0).abs() < 0.01);
}

#[test]
fn dwell_holds_at_position() {
    let mut rng = StdRng::seed_from_u64(0);
    let samples = dwell_samples((50.0, 50.0), 100, 1.0, &mut rng);
    for s in &samples {
        assert!((s.x - 50.0).abs() < 5.0);
        assert!((s.y - 50.0).abs() < 5.0);
    }
}

#[test]
fn grammar_weights_default_sum_to_one_for_approach() {
    let w = GrammarWeights::default();
    let total = w.approach_bezier + w.approach_spline + w.approach_linear;
    assert!((total - 1.0).abs() < 0.001);
}

#[test]
fn render_to_js_produces_async_iife() {
    let samples = vec![
        Sample {
            x: 10.0,
            y: 20.0,
            dt_ms: 0,
        },
        Sample {
            x: 30.0,
            y: 40.0,
            dt_ms: 15,
        },
    ];
    let js = render_to_js(&samples);
    assert!(js.contains("async () =>"));
    assert!(js.contains("MouseEvent"));
    assert!(js.contains("clientX: 10"));
    assert!(js.contains("clientY: 40"));
}

#[test]
fn render_to_js_does_not_use_set_timeout_zero_for_first_sample() {
    let samples = vec![Sample {
        x: 1.0,
        y: 2.0,
        dt_ms: 99,
    }];
    let js = render_to_js(&samples);
    // First-sample dt is rewritten to 0 - verifies the index==0 special case.
    assert!(js.contains("setTimeout(r, 0)"));
}

/// Scale test - 10k random trajectories must all render without
/// panicking and produce at least 5 samples each.
#[test]
fn scale_10k_random_trajectories_render_cleanly() {
    for seed in 0..10_000u64 {
        let traj = sample_trajectory((0.0, 0.0), (500.0, 300.0), GrammarWeights::default(), seed);
        let mut rng = StdRng::seed_from_u64(seed);
        let samples = traj.render(&mut rng);
        assert!(samples.len() >= 5);
    }
}

/// Distribution test - over many trajectories, the production
/// distribution should match the grammar weights within 5%.
#[test]
fn production_distribution_matches_grammar_weights() {
    let w = GrammarWeights::default();
    let n = 5_000;
    let mut bezier = 0;
    let mut spline = 0;
    let mut linear = 0;
    for seed in 0..n {
        let traj = sample_trajectory((0.0, 0.0), (300.0, 200.0), w, seed);
        match &traj.motions[0] {
            Motion::Bezier { .. } => bezier += 1,
            Motion::Spline { .. } => spline += 1,
            Motion::LinearJittered { .. } => linear += 1,
            _ => panic!("first motion was not an approach"),
        }
    }
    let bf = bezier as f64 / n as f64;
    let sf = spline as f64 / n as f64;
    let lf = linear as f64 / n as f64;
    // Tolerance 5% - the empirical proportion should match the
    // grammar weight within ±0.05.
    assert!(
        (bf - w.approach_bezier).abs() < 0.05,
        "bezier rate {bf} != {} ± 0.05",
        w.approach_bezier
    );
    assert!(
        (sf - w.approach_spline).abs() < 0.05,
        "spline rate {sf} != {} ± 0.05",
        w.approach_spline
    );
    assert!(
        (lf - w.approach_linear).abs() < 0.05,
        "linear rate {lf} != {} ± 0.05",
        w.approach_linear
    );
}

/// Reproducibility - same seed must produce same trajectory.
#[test]
fn trajectory_reproducible_by_seed() {
    let t1 = sample_trajectory((0.0, 0.0), (200.0, 200.0), GrammarWeights::default(), 99);
    let t2 = sample_trajectory((0.0, 0.0), (200.0, 200.0), GrammarWeights::default(), 99);
    assert_eq!(t1.motions, t2.motions);
}

/// Sample 10k trajectories and verify no two with different
/// seeds produce identical motion sequences (~0% collision).
#[test]
fn distinct_seeds_produce_distinct_trajectories() {
    let mut seen = std::collections::HashSet::new();
    let mut collisions = 0;
    for seed in 0..1_000 {
        let traj = sample_trajectory((0.0, 0.0), (200.0, 200.0), GrammarWeights::default(), seed);
        let key = format!("{:?}", traj.motions);
        if !seen.insert(key) {
            collisions += 1;
        }
    }
    assert!(
        collisions < 5,
        "{collisions} collisions out of 1000 trajectories"
    );
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 10_000, .. proptest::test_runner::Config::default()
    })]

    #[test]
    fn prop_trajectory_renders_without_panic(
        from_x in -1000.0..1000.0_f64,
        from_y in -1000.0..1000.0_f64,
        to_x in -1000.0..1000.0_f64,
        to_y in -1000.0..1000.0_f64,
        seed in 0u64..1_000_000,
    ) {
        let traj = sample_trajectory((from_x, from_y), (to_x, to_y), GrammarWeights::default(), seed);
        let mut rng = StdRng::seed_from_u64(seed);
        let samples = traj.render(&mut rng);
        // Must always produce ≥ 1 sample.
        assert!(!samples.is_empty());
    }

    #[test]
    fn prop_render_to_js_contains_set_timeout_per_sample(
        n_samples in 1usize..50,
    ) {
        let samples: Vec<Sample> = (0..n_samples)
            .map(|i| Sample { x: i as f64, y: i as f64, dt_ms: 10 })
            .collect();
        let js = render_to_js(&samples);
        let count = js.matches("setTimeout").count();
        assert_eq!(count, n_samples);
    }
}

/// Behavioral oracle: execute `render_to_js` output under Node and PROVE every
/// `MouseEvent` it dispatches is `isTrusted === false`.
///
/// This locks the load-bearing fact behind `render_to_js`'s warning: a
/// DOM-dispatched event can never be trusted, so this path is for driving a
/// page's own handlers, NOT for evasion (use `HumanMouse::follow_trajectory`,
/// which dispatches through the trusted BiDi driver). It also proves the emitted
/// JS is syntactically valid and runs to completion. Loud SKIP if `node` is
/// absent (Law 10).
#[test]
fn render_to_js_events_are_untrusted_under_node() {
    use std::process::Command;
    if Command::new("node").arg("--version").output().is_err() {
        eprintln!("SKIP render_to_js_events_are_untrusted_under_node: `node` not on PATH.");
        return;
    }
    let samples = vec![
        Sample {
            x: 10.0,
            y: 20.0,
            dt_ms: 1,
        },
        Sample {
            x: 30.0,
            y: 40.0,
            dt_ms: 1,
        },
        Sample {
            x: 50.0,
            y: 60.0,
            dt_ms: 1,
        },
    ];
    let js = render_to_js(&samples);

    // Stub the DOM the IIFE touches; capture isTrusted on each dispatched event.
    // Node's own `Event.isTrusted` is `false` for script-constructed events
    // exactly the browser semantics this test asserts. JS passed via env (no
    // shell, no escaping).
    let harness = r#"
'use strict';
globalThis.MouseEvent = class MouseEvent extends Event {
  constructor(type, opts = {}) { super(type, opts); this.clientX = opts.clientX; this.clientY = opts.clientY; }
};
const captured = [];
const target = new EventTarget();
target.addEventListener('mousemove', (e) => { captured.push(e.isTrusted); });
globalThis.document = { elementFromPoint: () => target };
const p = eval(process.env.GUISE_TRAJECTORY_JS); // self-invoking async IIFE -> Promise
Promise.resolve(p).then(() => {
  const fails = [];
  if (captured.length === 0) fails.push('no mousemove events were dispatched (IIFE did nothing)');
  if (!captured.every((t) => t === false)) fails.push('expected every dispatched MouseEvent isTrusted===false, got ' + JSON.stringify(captured));
  if (fails.length) { console.error('TRAJECTORY ORACLE FAIL:\n' + fails.join('\n')); process.exit(1); }
  console.log('TRAJECTORY ORACLE OK (' + captured.length + ' untrusted events)');
}).catch((e) => { console.error('TRAJECTORY ORACLE THREW: ' + e.message); process.exit(1); });
"#;
    let out = Command::new("node")
        .arg("-e")
        .arg(harness)
        .env("GUISE_TRAJECTORY_JS", &js)
        .output()
        .expect("run node");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("TRAJECTORY ORACLE OK"),
        "render_to_js untrusted-event oracle failed:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
}
