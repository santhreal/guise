//! Sample-geometry generators for behavioral-grammar motion terminals.
//!
//! Each function renders one [`Motion`](super::Motion) variant into a
//! sequence of pointer-event [`Sample`](super::Sample)s. All noise is
//! drawn from the caller-supplied `StdRng`, so the same seed always
//! yields the same geometry.

use rand::{rngs::StdRng, Rng};

use super::Sample;

pub(crate) fn bezier_samples(
    p0: (f64, f64),
    p1: (f64, f64),
    p2: (f64, f64),
    p3: (f64, f64),
    samples: usize,
    t_jitter: f64,
    rng: &mut StdRng,
) -> Vec<Sample> {
    let mut out = Vec::with_capacity(samples);
    let step = 1.0 / (samples as f64).max(1.0);
    let mut last_t = 0.0;
    for i in 0..samples {
        let nominal = (i as f64) * step;
        let jitter = (rng.gen::<f64>() - 0.5) * 2.0 * t_jitter;
        let t = (nominal + jitter).clamp(0.0, 1.0);
        let omt = 1.0 - t;
        let x = omt.powi(3) * p0.0
            + 3.0 * omt.powi(2) * t * p1.0
            + 3.0 * omt * t.powi(2) * p2.0
            + t.powi(3) * p3.0;
        let y = omt.powi(3) * p0.1
            + 3.0 * omt.powi(2) * t * p1.1
            + 3.0 * omt * t.powi(2) * p2.1
            + t.powi(3) * p3.1;
        // Sub-frame timing: 5-25ms per sample.
        let dt_ms = (5.0 + 20.0 * (t - last_t).abs() * (samples as f64)).clamp(3.0, 30.0) as u64;
        last_t = t;
        out.push(Sample { x, y, dt_ms });
    }
    out
}

pub(crate) fn catmull_rom_samples(
    control: &[(f64, f64)],
    samples: usize,
    rng: &mut StdRng,
) -> Vec<Sample> {
    // Catmull-Rom: smooth interpolation through control points.
    // Need at least 4 control points; pad by repeating the last. With no control
    // points there is no curve to sample, return empty rather than panicking on
    // `last()` of an empty slice.
    let mut pts = control.to_vec();
    let Some(&last) = pts.last() else {
        return Vec::new();
    };
    while pts.len() < 4 {
        pts.push(last);
    }
    let mut out = Vec::with_capacity(samples);
    let segments = pts.len() - 3;
    let samples_per_seg = samples / segments.max(1);
    for seg in 0..segments {
        let (p0, p1, p2, p3) = (pts[seg], pts[seg + 1], pts[seg + 2], pts[seg + 3]);
        for i in 0..samples_per_seg {
            let t = (i as f64) / (samples_per_seg as f64);
            let t2 = t * t;
            let t3 = t2 * t;
            // Catmull-Rom kernel.
            let f0 = -0.5 * t3 + t2 - 0.5 * t;
            let f1 = 1.5 * t3 - 2.5 * t2 + 1.0;
            let f2 = -1.5 * t3 + 2.0 * t2 + 0.5 * t;
            let f3 = 0.5 * t3 - 0.5 * t2;
            let x = f0 * p0.0 + f1 * p1.0 + f2 * p2.0 + f3 * p3.0;
            let y = f0 * p0.1 + f1 * p1.1 + f2 * p2.1 + f3 * p3.1;
            let dt_ms = rng.gen_range(5u64..20u64);
            out.push(Sample { x, y, dt_ms });
        }
    }
    out
}

pub(crate) fn linear_jittered_samples(
    from: (f64, f64),
    to: (f64, f64),
    samples: usize,
    jitter_px: f64,
    rng: &mut StdRng,
) -> Vec<Sample> {
    let mut out = Vec::with_capacity(samples);
    let dx = to.0 - from.0;
    let dy = to.1 - from.1;
    for i in 0..samples {
        let t = (i as f64) / ((samples - 1).max(1) as f64);
        let jx = (rng.gen::<f64>() - 0.5) * 2.0 * jitter_px;
        let jy = (rng.gen::<f64>() - 0.5) * 2.0 * jitter_px;
        let x = from.0 + dx * t + jx;
        let y = from.1 + dy * t + jy;
        let dt_ms = rng.gen_range(8u64..18u64);
        out.push(Sample { x, y, dt_ms });
    }
    out
}

pub(crate) fn overshoot_samples(
    target: (f64, f64),
    distance_px: f64,
    recovery_ms: u64,
    rng: &mut StdRng,
) -> Vec<Sample> {
    let angle: f64 = rng.gen_range(0.0..(2.0 * std::f64::consts::PI));
    let overshot_x = target.0 + distance_px * angle.cos();
    let overshot_y = target.1 + distance_px * angle.sin();
    vec![
        Sample {
            x: overshot_x,
            y: overshot_y,
            dt_ms: 10,
        },
        Sample {
            x: target.0,
            y: target.1,
            dt_ms: recovery_ms,
        },
    ]
}

pub(crate) fn correction_samples(
    from: (f64, f64),
    to: (f64, f64),
    samples: usize,
    rng: &mut StdRng,
) -> Vec<Sample> {
    linear_jittered_samples(from, to, samples, 1.0, rng)
}

pub(crate) fn dwell_samples(
    at: (f64, f64),
    duration_ms: u64,
    micro_jitter_px: f64,
    rng: &mut StdRng,
) -> Vec<Sample> {
    // Dwell = a single waypoint sample with the dwell duration. The
    // micro-jitter renders as small position offsets across two
    // samples.
    let jx = (rng.gen::<f64>() - 0.5) * 2.0 * micro_jitter_px;
    let jy = (rng.gen::<f64>() - 0.5) * 2.0 * micro_jitter_px;
    vec![
        Sample {
            x: at.0 + jx,
            y: at.1 + jy,
            dt_ms: duration_ms / 2,
        },
        Sample {
            x: at.0,
            y: at.1,
            dt_ms: duration_ms / 2,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn catmull_rom_with_no_control_points_returns_empty_not_panic() {
        // Regression: an empty control slice used to panic on `last().unwrap()`.
        let mut rng = StdRng::seed_from_u64(1);
        let out = catmull_rom_samples(&[], 16, &mut rng);
        assert!(out.is_empty());
    }

    #[test]
    fn catmull_rom_pads_fewer_than_four_control_points() {
        // 1–3 control points must still render a curve by repeating the last.
        let mut rng = StdRng::seed_from_u64(2);
        for control in [
            vec![(0.0, 0.0)],
            vec![(0.0, 0.0), (10.0, 5.0)],
            vec![(0.0, 0.0), (10.0, 5.0), (20.0, 0.0)],
        ] {
            let out = catmull_rom_samples(&control, 12, &mut rng);
            assert!(
                !out.is_empty(),
                "{} control points should still produce samples",
                control.len()
            );
        }
    }

    #[test]
    fn catmull_rom_is_deterministic_for_a_fixed_seed() {
        let control = vec![(0.0, 0.0), (10.0, 5.0), (20.0, 0.0), (30.0, 8.0)];
        let a = catmull_rom_samples(&control, 24, &mut StdRng::seed_from_u64(7));
        let b = catmull_rom_samples(&control, 24, &mut StdRng::seed_from_u64(7));
        assert_eq!(a, b);
    }
}
