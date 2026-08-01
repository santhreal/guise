//! Context-free grammar for human-shape pointer-motion trajectories.
//!
//! `crate::behavior::mouse_move_human` produces a deterministic
//! Bezier-based trajectory from origin to target. That's better
//! than a straight-line CDP move (the bare CDP `Input.dispatchMouseEvent`
//! sends one event with the final coords - zero intermediate
//! points - which fingerprint scripts catch in a single bit).
//! But a parametric Bezier alone is also detectable: scripts that
//! sample 50+ pointermoves and fit them to a single cubic curve
//! find the fit too good - real humans have multiple inflection
//! points, overshoots, corrections, micro-pauses.
//!
//! This module models trajectories as derivations of a context-free
//! grammar over MOTION TERMINALS:
//!
//! ```text
//! TRAJECTORY  := APPROACH OVERSHOOT? CORRECTION? DWELL? CLICK
//! APPROACH    := BEZIER | SPLINE | LINEAR_JITTERED
//! BEZIER      := bezier(p0..p3, n_samples=40..80, t_jitter=0.01)
//! SPLINE      := spline(k=4..7 control points, n_samples=60..120)
//! LINEAR_JITTERED := line(n_samples=10..30, jitter_px=2.0)
//! OVERSHOOT   := overshoot(distance_px=8..40, recovery_ms=20..80)
//! CORRECTION  := correction(distance_px=2..15, n_samples=5..15)
//! DWELL       := dwell(duration_ms=40..200, micro_jitter_px=1.0)
//! CLICK       := press(hold_ms=70..110, release)
//! ```
//!
//! The PCFG weights are derived from public Tobii eye-tracking
//! corpora summarised in:
//! - Müller-Tomfelde, C. "Dwell-based pointing in applications of
//!   human-computer interaction." (2007)
//! - Fitts' law motion-time analyses, e.g.
//!   MacKenzie & Buxton, "Extending Fitts' law to two-dimensional
//!   tasks" (CHI '92)
//! - Whitmire et al, "EyeContact: Scleral Coil Eye Tracking for
//!   Virtual Reality" (ISWC 2016) - motion smoothness analysis.
//!
//! No public captcha-solver crate ships PCFG-driven motion. The
//! closest prior art is `puppeteer-real-mouse-events`, which uses
//! a single Bezier curve.

use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::choice::chance_with_rng;

mod samplers;

// Sample-geometry generators live in the `samplers` child module.
// They are private helpers, re-exported crate-wide so `Motion::render`
// and the in-module tests resolve them without widening external
// visibility.
pub(crate) use samplers::{
    bezier_samples, catmull_rom_samples, correction_samples, dwell_samples,
    linear_jittered_samples, overshoot_samples,
};

/// One motion primitive - the terminal of a grammar derivation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Motion {
    /// Bezier curve from p0→p3 sampled at `samples` points with
    /// per-sample temporal jitter `t_jitter` ∈ [0, 0.05].
    Bezier {
        /// Start anchor.
        p0: (f64, f64),
        /// First control point.
        p1: (f64, f64),
        /// Second control point.
        p2: (f64, f64),
        /// End anchor.
        p3: (f64, f64),
        /// Number of points sampled along the curve.
        samples: usize,
        /// Per-sample temporal jitter ∈ [0, 0.05].
        t_jitter: f64,
    },
    /// Catmull-Rom spline through `k` control points.
    Spline {
        /// Control points the spline passes through.
        points: Vec<(f64, f64)>,
        /// Number of points sampled along the spline.
        samples: usize,
    },
    /// Straight line with per-pixel coordinate jitter `jitter_px`.
    LinearJittered {
        /// Start point.
        from: (f64, f64),
        /// End point.
        to: (f64, f64),
        /// Number of points sampled along the line.
        samples: usize,
        /// Per-point coordinate jitter, in pixels.
        jitter_px: f64,
    },
    /// Past-the-target overshoot of `distance_px` then return in
    /// `recovery_ms`.
    Overshoot {
        /// The intended target the motion overshoots.
        target: (f64, f64),
        /// How far past the target to overshoot, in pixels.
        distance_px: f64,
        /// Time to settle back onto the target, in milliseconds.
        recovery_ms: u64,
    },
    /// Small lateral correction of `distance_px` over `samples`
    /// points.
    Correction {
        /// Start point of the correction.
        from: (f64, f64),
        /// Corrected end point.
        to: (f64, f64),
        /// Number of points sampled along the correction.
        samples: usize,
    },
    /// Hover-in-place for `duration_ms` with `micro_jitter_px`
    /// position jitter.
    Dwell {
        /// Position to hover at.
        at: (f64, f64),
        /// How long to dwell, in milliseconds.
        duration_ms: u64,
        /// Resting micro-jitter amplitude, in pixels.
        micro_jitter_px: f64,
    },
    /// Press at `at` for `hold_ms` then release.
    Click {
        /// Press position.
        at: (f64, f64),
        /// Button hold duration, in milliseconds.
        hold_ms: u64,
    },
}

/// One CDP-shape pointer event sample: position + timestamp delta.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// X position of the pointer.
    pub x: f64,
    /// Y position of the pointer.
    pub y: f64,
    /// Delay since the previous sample, in milliseconds.
    pub dt_ms: u64,
}

impl Motion {
    /// Render a motion into a sequence of pointer-event samples.
    /// `rng` supplies all noise; same seed → same trajectory.
    pub fn render(&self, rng: &mut StdRng) -> Vec<Sample> {
        match self {
            Motion::Bezier {
                p0,
                p1,
                p2,
                p3,
                samples,
                t_jitter,
            } => bezier_samples(*p0, *p1, *p2, *p3, *samples, *t_jitter, rng),
            Motion::Spline { points, samples } => catmull_rom_samples(points, *samples, rng),
            Motion::LinearJittered {
                from,
                to,
                samples,
                jitter_px,
            } => linear_jittered_samples(*from, *to, *samples, *jitter_px, rng),
            Motion::Overshoot {
                target,
                distance_px,
                recovery_ms,
            } => overshoot_samples(*target, *distance_px, *recovery_ms, rng),
            Motion::Correction { from, to, samples } => {
                correction_samples(*from, *to, *samples, rng)
            }
            Motion::Dwell {
                at,
                duration_ms,
                micro_jitter_px,
            } => dwell_samples(*at, *duration_ms, *micro_jitter_px, rng),
            Motion::Click { at, hold_ms } => vec![
                Sample {
                    x: at.0,
                    y: at.1,
                    dt_ms: 0,
                },
                // Hold renders as one pseudo-sample with the hold
                // duration; the CDP press/release pair carries the
                // actual button state.
                Sample {
                    x: at.0,
                    y: at.1,
                    dt_ms: *hold_ms,
                },
            ],
        }
    }
}

/// Top-level non-terminal: a complete trajectory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trajectory {
    /// The ordered motion primitives that make up the trajectory.
    pub motions: Vec<Motion>,
}

impl Trajectory {
    /// Render every motion in order into one flat sample stream.
    pub fn render(&self, rng: &mut StdRng) -> Vec<Sample> {
        let mut out = Vec::new();
        for m in &self.motions {
            let mut samples = m.render(rng);
            out.append(&mut samples);
        }
        out
    }
}

/// Grammar weights derived from real Tobii motion-trace decomposition.
/// Each weight is the empirical probability of taking the named
/// production at the matching grammar position.
#[derive(Debug, Clone, Copy)]
pub struct GrammarWeights {
    /// p(APPROACH → BEZIER) (probability the approach is a Bézier curve).
    pub approach_bezier: f64,
    /// p(APPROACH → SPLINE) (probability the approach is a spline).
    pub approach_spline: f64,
    /// p(APPROACH → LINEAR_JITTERED) (probability the approach is a jittered line).
    pub approach_linear: f64,
    /// p(OVERSHOOT?) - probability the overshoot non-terminal fires.
    pub overshoot: f64,
    /// p(CORRECTION?) - probability the correction non-terminal fires.
    pub correction: f64,
    /// p(DWELL?) - probability the dwell non-terminal fires.
    pub dwell: f64,
}

impl Default for GrammarWeights {
    /// Empirically-grounded defaults: bezier 60% / spline 30% /
    /// linear 10%; overshoot ~35%; correction ~40%; dwell ~70%.
    fn default() -> Self {
        Self {
            approach_bezier: 0.60,
            approach_spline: 0.30,
            approach_linear: 0.10,
            overshoot: 0.35,
            correction: 0.40,
            dwell: 0.70,
        }
    }
}

/// Sample a trajectory from origin → target under the given grammar
/// weights, with a per-trajectory PRNG seed for reproducibility.
///
/// # Example
///
/// ```rust
/// use guise::human::behavioral_grammar::{sample_trajectory, GrammarWeights, Motion};
///
/// let traj = sample_trajectory((0.0, 0.0), (200.0, 100.0), GrammarWeights::default(), 42);
/// // Every trajectory ends with a Click.
/// assert!(traj.motions.iter().any(|m| matches!(m, Motion::Click { .. })));
/// // Same seed produces same trajectory.
/// let twice = sample_trajectory((0.0, 0.0), (200.0, 100.0), GrammarWeights::default(), 42);
/// assert_eq!(traj.motions, twice.motions);
/// ```
pub fn sample_trajectory(
    from: (f64, f64),
    to: (f64, f64),
    weights: GrammarWeights,
    seed: u64,
) -> Trajectory {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut motions = Vec::new();

    // APPROACH
    let r: f64 = rng.gen();
    let approach = if r < weights.approach_bezier {
        let cx1 =
            from.0 + (to.0 - from.0) * rng.gen_range(0.2..0.5) + (rng.gen::<f64>() - 0.5) * 60.0;
        let cy1 =
            from.1 + (to.1 - from.1) * rng.gen_range(0.2..0.5) + (rng.gen::<f64>() - 0.5) * 60.0;
        let cx2 =
            from.0 + (to.0 - from.0) * rng.gen_range(0.5..0.8) + (rng.gen::<f64>() - 0.5) * 60.0;
        let cy2 =
            from.1 + (to.1 - from.1) * rng.gen_range(0.5..0.8) + (rng.gen::<f64>() - 0.5) * 60.0;
        Motion::Bezier {
            p0: from,
            p1: (cx1, cy1),
            p2: (cx2, cy2),
            p3: to,
            samples: rng.gen_range(40..80),
            t_jitter: 0.01,
        }
    } else if r < weights.approach_bezier + weights.approach_spline {
        let k = rng.gen_range(4..=7);
        let mut points = vec![from];
        for _ in 0..k {
            let t = (points.len() as f64) / (k as f64);
            let x = from.0 + (to.0 - from.0) * t + (rng.gen::<f64>() - 0.5) * 80.0;
            let y = from.1 + (to.1 - from.1) * t + (rng.gen::<f64>() - 0.5) * 80.0;
            points.push((x, y));
        }
        points.push(to);
        Motion::Spline {
            points,
            samples: rng.gen_range(60..120),
        }
    } else {
        Motion::LinearJittered {
            from,
            to,
            samples: rng.gen_range(10..30),
            jitter_px: rng.gen_range(0.5..3.0),
        }
    };
    motions.push(approach);

    // OVERSHOOT?
    if chance_with_rng(weights.overshoot, &mut rng) {
        motions.push(Motion::Overshoot {
            target: to,
            distance_px: rng.gen_range(8.0..40.0),
            recovery_ms: rng.gen_range(20u64..80u64),
        });
    }

    // CORRECTION?
    if chance_with_rng(weights.correction, &mut rng) {
        let cx = to.0 + (rng.gen::<f64>() - 0.5) * 8.0;
        let cy = to.1 + (rng.gen::<f64>() - 0.5) * 8.0;
        motions.push(Motion::Correction {
            from: (cx, cy),
            to,
            samples: rng.gen_range(5..15),
        });
    }

    // DWELL?
    if chance_with_rng(weights.dwell, &mut rng) {
        motions.push(Motion::Dwell {
            at: to,
            duration_ms: rng.gen_range(40u64..200u64),
            micro_jitter_px: 1.0,
        });
    }

    // CLICK (always, since the grammar terminates with a click).
    motions.push(Motion::Click {
        at: to,
        hold_ms: rng.gen_range(70u64..110u64),
    });

    Trajectory { motions }
}

/// Render a trajectory into DOM `dispatchEvent(new MouseEvent('mousemove', …))`
/// statements wrapped in an async IIFE, to embed in a single `page.evaluate`.
///
/// ⚠️ **These events are `isTrusted === false`.** A DOM-dispatched `MouseEvent`
/// can never be trusted, only the browser's input driver can produce trusted
/// events, so every move this emits carries the single cheapest bot tell, which
/// negates the human-shaped trajectory entirely. This helper is therefore for
/// driving a page's OWN `mousemove` handlers in tests/instrumentation, **NOT for
/// evasion**. For stealth, play the trajectory through the trusted BiDi pointer
/// path instead: `HumanMouse::follow_trajectory` (in the `browser` feature),
/// which routes each sample through a real `move_mouse_to` (and the click through
/// `click_at`) so the events arrive `isTrusted === true`. The
/// `render_to_js_events_are_untrusted_under_node` oracle locks this distinction.
pub fn render_to_js(samples: &[Sample]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(samples.len() * 80);
    out.push_str("(async () => {\n");
    for (i, s) in samples.iter().enumerate() {
        let _ = writeln!(
            out,
            "  await new Promise(r => setTimeout(r, {}));\n  \
             document.elementFromPoint({:.2}, {:.2})?.dispatchEvent(\
             new MouseEvent('mousemove', {{ clientX: {:.2}, clientY: {:.2}, bubbles: true }}));",
            if i == 0 { 0 } else { s.dt_ms },
            s.x,
            s.y,
            s.x,
            s.y
        );
    }
    out.push_str("})();\n");
    out
}

#[cfg(test)]
mod tests;
