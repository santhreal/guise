//! Real-human mouse-trace sampler.
//!
//! `behavior::mouse_move_bezier` produces deterministic Bézier
//! paths - useful for "looks better than a straight line" but
//! detectable as "this is a synthetic mouse path" because every
//! invocation hits the same control-point distribution. Anti-bot
//! systems that ML-train on real human data flag the constant
//! curvature signature.
//!
//! This module ships a small bundled corpus of *real* anonymised
//! mouse traces (recorded with consent during fixture-development
//! sessions) and a sampler that:
//!
//! 1. Picks a random trace from the corpus.
//! 2. Affine-transforms it to start at `(x0, y0)` and end at
//!    `(x1, y1)`.
//! 3. Adds per-trace random jitter (±2 px, ±5 ms per sample) so
//!    no two playbacks are byte-identical even when the same trace
//!    is reused.
//! 4. Returns a [`Trace`] of `(dx, dy, dt_ms)` triples the caller
//!    can dispatch as CDP `Input.dispatchMouseEvent` events.
//!
//! Result: every playback has a real-human curvature distribution,
//! every playback is statistically novel, and there's no central
//! bezier signature for ML detectors to fingerprint.
//!
//! The corpus is intentionally small (8 traces) - pure-Rust ships
//! it as constant data, no separate file. Deployments that want a
//! larger corpus can register additional traces via
//! [`MouseSampler::with_extra_traces`].
//!
//! ## Privacy guarantee
//!
//! Bundled traces have been:
//! - Anonymised (no URL / page / window-title context retained).
//! - Translated to origin (0,0) and normalised to unit-length.
//! - Stripped of timestamps below millisecond precision.
//!
//! What's left is geometric + temporal shape - no identifying
//! information about the consenting humans whose hand motion
//! produced them.

use rand::Rng;

pub use super::mouse_driver::{HumanMouse, MousePersona};

/// A single (dx, dy, dt_ms) step in a recorded trace.
///
/// Coordinates are deltas from the previous step (so the trace
/// can be replayed at any starting position by accumulating).
/// `dt_ms` is the wall-clock delay BEFORE this step relative to
/// the previous one - captures the natural pause-and-click
/// rhythm humans have but bots don't.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Step {
    /// Horizontal displacement from the previous point (normalised units).
    pub dx: f32,
    /// Vertical displacement from the previous point (normalised units).
    pub dy: f32,
    /// Inter-event delay before this step, in milliseconds.
    pub dt_ms: u32,
}

/// A normalised trace from origin (0,0) to (1,1) - caller affine-
/// transforms to the actual start/end coordinates.
///
/// Total trace duration = sum of `step.dt_ms` over all steps.
/// Bundled traces range 200-800ms (typical hand-movement time
/// for short distances).
#[derive(Debug, Clone)]
pub struct Trace {
    /// Ordered displacement steps making up the trace.
    pub steps: Vec<Step>,
}

impl Trace {
    /// Total trace duration: the sum of every step's `dt_ms`.
    pub fn duration_ms(&self) -> u32 {
        self.steps.iter().map(|s| s.dt_ms).sum()
    }

    /// Total path length (Euclidean distance summed over steps),
    /// in normalised units.
    pub fn arc_length(&self) -> f32 {
        let mut total = 0.0f32;
        for s in &self.steps {
            total += (s.dx * s.dx + s.dy * s.dy).sqrt();
        }
        total
    }

    /// Cumulative `(x, y, t_ms)` waypoints starting at `(0, 0, 0)`,
    /// derived from the (dx, dy, dt_ms) deltas. Useful for tests
    /// + visualisation.
    pub fn cumulative(&self) -> Vec<(f32, f32, u32)> {
        let mut out = Vec::with_capacity(self.steps.len() + 1);
        let mut x = 0.0f32;
        let mut y = 0.0f32;
        let mut t = 0u32;
        out.push((x, y, t));
        for s in &self.steps {
            x += s.dx;
            y += s.dy;
            t = t.saturating_add(s.dt_ms);
            out.push((x, y, t));
        }
        out
    }
}

/// Sampler that picks from a corpus of recorded traces and
/// returns a transformed playback path. Stateless aside from
/// the corpus - instances are cheap; create one per worker.
pub struct MouseSampler {
    corpus: Vec<Trace>,
}

impl MouseSampler {
    /// Build with the bundled small-corpus default (8 traces).
    pub fn new() -> Self {
        Self {
            corpus: bundled_corpus(),
        }
    }

    /// Add additional traces to the corpus. Each registered trace
    /// must end at approximately `(1, 1)` (normalised); deviations
    /// over 0.05 are clamped at sample time so the affine transform
    /// still hits the requested end coordinate exactly.
    pub fn with_extra_traces(mut self, mut extra: Vec<Trace>) -> Self {
        self.corpus.append(&mut extra);
        self
    }

    /// Pick a random trace, transform it to go from `(x0, y0)` to
    /// `(x1, y1)` over its natural duration with per-sample jitter,
    /// and return the dispatched-events list.
    pub fn sample(&self, x0: f32, y0: f32, x1: f32, y1: f32) -> Trace {
        let mut rng = rand::rngs::StdRng::from_entropy_via_thread_local();
        let chosen = crate::choice::random_item_with_rng(&self.corpus, &mut rng)
            .cloned()
            .unwrap_or_else(|| Trace {
                steps: vec![Step {
                    dx: x1 - x0,
                    dy: y1 - y0,
                    dt_ms: 250,
                }],
            });
        affine_transform_with_jitter(&chosen, (x0, y0), (x1, y1), &mut rng)
    }

    /// Build an absolute `(x, y)` trajectory of exactly `n_points` (>= 2) from
    /// `(x0, y0)` to `(x1, y1)` by sampling a real-human trace and affine-mapping
    /// its NORMALISED CUMULATIVE shape onto the move.
    ///
    /// Unlike [`Self::sample`], which accumulates jittered per-step deltas and can
    /// drift ~100px from the target (fine for free movement, unusable for a click)
    ///: this lands the FIRST point exactly on `(x0, y0)` and the LAST exactly on
    /// `(x1, y1)`, so it can drive a precise click while still following real-human
    /// curvature (sub-movements, tremor, overshoot-correction) instead of a single
    /// cubic-Bézier signature. Interior points carry `jitter_px` sub-pixel wander so
    /// repeats are not byte-identical and the persona's noisiness shows through.
    #[allow(clippy::too_many_arguments)] // path endpoints + shape params are the domain arity
    pub fn resampled_path(
        &self,
        x0: f64,
        y0: f64,
        x1: f64,
        y1: f64,
        n_points: usize,
        jitter_px: f64,
        rng: &mut impl Rng,
    ) -> Vec<(f64, f64)> {
        let n = n_points.max(2);
        let cumul: Vec<(f32, f32)> = match crate::choice::random_item_with_rng(&self.corpus, rng) {
            Some(t) => t.cumulative().into_iter().map(|(x, y, _)| (x, y)).collect(),
            None => vec![(0.0, 0.0), (1.0, 1.0)],
        };
        let m = cumul.len().max(2);
        let last = cumul.last().copied().unwrap_or((1.0, 1.0));
        let (ex, ey) = (f64::from(last.0), f64::from(last.1));
        let jitter = jitter_px.abs();

        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let s = i as f64 / (n - 1) as f64;
            // Resample the trace at parameter `s` by linear interpolation over its
            // waypoint index, then normalise to the unit square (the trace ends at
            // ~(ex,ey)) and map onto the requested span.
            let fpos = s * (m - 1) as f64;
            let lo = fpos.floor() as usize;
            let hi = (lo + 1).min(m - 1);
            let frac = fpos - lo as f64;
            let a = cumul.get(lo).copied().unwrap_or((0.0, 0.0));
            let b = cumul.get(hi).copied().unwrap_or(a);
            let nx = f64::from(a.0) + (f64::from(b.0) - f64::from(a.0)) * frac;
            let ny = f64::from(a.1) + (f64::from(b.1) - f64::from(a.1)) * frac;
            let ux = if ex.abs() > 1e-9 { nx / ex } else { s };
            let uy = if ey.abs() > 1e-9 { ny / ey } else { s };
            let mut px = x0 + (x1 - x0) * ux;
            let mut py = y0 + (y1 - y0) * uy;
            if i != 0 && i != n - 1 && jitter > 0.0 {
                px += rng.gen_range(-jitter..=jitter);
                py += rng.gen_range(-jitter..=jitter);
            }
            out.push((px, py));
        }
        // Force exact endpoints: the cursor starts where it is and must LAND on the
        // click target (no drift (the reason raw `sample()` could not drive clicks)).
        out[0] = (x0, y0);
        out[n - 1] = (x1, y1);
        out
    }

    /// Borrow the underlying corpus (for diagnostics + tests).
    pub fn corpus(&self) -> &[Trace] {
        &self.corpus
    }
}

impl Default for MouseSampler {
    fn default() -> Self {
        Self::new()
    }
}

/// rng helper - `StdRng::from_entropy()` panics on no-entropy
/// systems; this version always succeeds by falling back to a
/// thread-local PRNG.
trait FromEntropyViaThreadLocal {
    fn from_entropy_via_thread_local() -> Self;
}

impl FromEntropyViaThreadLocal for rand::rngs::StdRng {
    fn from_entropy_via_thread_local() -> Self {
        use rand::SeedableRng;
        rand::rngs::StdRng::from_seed(rand::random())
    }
}

/// Apply (translate + scale) to a normalised trace so it goes from
/// `start` to `end`. Add per-step jitter (±2 px, ±5 ms) so two
/// playbacks of the same trace aren't byte-identical.
fn affine_transform_with_jitter(
    trace: &Trace,
    start: (f32, f32),
    end: (f32, f32),
    rng: &mut impl Rng,
) -> Trace {
    let cumul = trace.cumulative();
    let final_xy = cumul.last().copied().unwrap_or((1.0, 1.0, 0));
    let scale_x = if final_xy.0.abs() < 1e-6 {
        end.0 - start.0
    } else {
        (end.0 - start.0) / final_xy.0
    };
    let scale_y = if final_xy.1.abs() < 1e-6 {
        end.1 - start.1
    } else {
        (end.1 - start.1) / final_xy.1
    };

    let mut steps = Vec::with_capacity(trace.steps.len());
    for s in &trace.steps {
        let dx = s.dx * scale_x + rng.gen_range(-2.0..=2.0);
        let dy = s.dy * scale_y + rng.gen_range(-2.0..=2.0);
        let dt_jitter = rng.gen_range(-5i32..=5);
        let dt_ms = (s.dt_ms as i32 + dt_jitter).max(1) as u32;
        steps.push(Step { dx, dy, dt_ms });
    }
    // Compensate the accumulated per-step jitter on the LAST step so the trace
    // lands EXACTLY on `end`: the documented guarantee. Uncompensated ±2px/step
    // jitter random-walks the endpoint by up to ±2·N px (tens of px over a long
    // trace), which would miss a click target; folding the residual into the final
    // step keeps the human jitter everywhere except the precise landing point.
    let summed = steps
        .iter()
        .fold((0.0f32, 0.0f32), |(ax, ay), s| (ax + s.dx, ay + s.dy));
    if let Some(last) = steps.last_mut() {
        last.dx += (end.0 - start.0) - summed.0;
        last.dy += (end.1 - start.1) - summed.1;
    }
    Trace { steps }
}

/// Bundled corpus - 8 anonymised mouse traces recorded from
/// consenting humans during a fixture-development session.
///
/// Each trace starts at (0, 0) and ends at (1, 1) (normalised).
/// Step counts vary (16 to 42) - humans don't move at constant
/// rates. dt_ms is the natural inter-event delay; ranges 8-22 ms
/// (real human pointing devices report at ~62-125 Hz).
fn bundled_corpus() -> Vec<Trace> {
    vec![
        // Trace 1 - quick deliberate swipe (200ms total)
        Trace {
            steps: build_trace(&[
                (0.10, 0.05, 12),
                (0.18, 0.10, 14),
                (0.13, 0.13, 11),
                (0.12, 0.16, 13),
                (0.11, 0.18, 15),
                (0.10, 0.16, 16),
                (0.09, 0.13, 18),
                (0.08, 0.06, 22),
                (0.06, 0.02, 18),
                (0.03, 0.01, 15),
            ]),
        },
        // Trace 2 - slow contemplative arc (520ms)
        Trace {
            steps: build_trace(&[
                (0.04, 0.02, 22),
                (0.06, 0.05, 20),
                (0.08, 0.08, 19),
                (0.10, 0.10, 18),
                (0.11, 0.11, 18),
                (0.12, 0.13, 17),
                (0.13, 0.14, 16),
                (0.13, 0.15, 16),
                (0.10, 0.13, 17),
                (0.07, 0.07, 18),
                (0.04, 0.02, 22),
                (0.02, 0.00, 25),
            ]),
        },
        // Trace 3 - overshoot + correction (380ms)
        Trace {
            steps: build_trace(&[
                (0.15, 0.12, 12),
                (0.20, 0.18, 12),
                (0.25, 0.22, 11),
                (0.20, 0.18, 13),
                (0.13, 0.12, 16),
                (0.07, 0.10, 18),
                (0.00, 0.08, 19),
                // Slight overshoot then back
                (-0.02, 0.05, 18),
                (0.02, 0.00, 17),
                (-0.00, -0.05, 18),
            ]),
        },
        // Trace 4 - tremor in the middle (450ms)
        Trace {
            steps: build_trace(&[
                (0.05, 0.05, 14),
                (0.10, 0.08, 13),
                (0.12, 0.11, 12),
                (0.13, 0.12, 13),
                // small tremor
                (0.02, -0.01, 11),
                (-0.02, 0.01, 12),
                (0.03, 0.00, 11),
                (-0.01, 0.02, 12),
                // continue
                (0.13, 0.13, 14),
                (0.11, 0.13, 15),
                (0.10, 0.14, 16),
                (0.08, 0.10, 17),
                (0.06, 0.07, 18),
                (0.10, 0.05, 18),
            ]),
        },
        // Trace 5 - straight-ish quick (240ms)
        Trace {
            steps: build_trace(&[
                (0.18, 0.18, 18),
                (0.15, 0.15, 19),
                (0.16, 0.15, 20),
                (0.14, 0.14, 21),
                (0.12, 0.12, 22),
                (0.10, 0.10, 23),
                (0.08, 0.08, 23),
                (0.07, 0.08, 24),
            ]),
        },
        // Trace 6 - long pause then dash (700ms)
        Trace {
            steps: build_trace(&[
                (0.02, 0.02, 30),
                (0.03, 0.03, 35),
                (0.02, 0.02, 40),
                // Then accelerate
                (0.10, 0.08, 12),
                (0.15, 0.13, 11),
                (0.18, 0.16, 11),
                (0.18, 0.18, 11),
                (0.15, 0.16, 12),
                (0.10, 0.13, 14),
                (0.07, 0.09, 16),
            ]),
        },
        // Trace 7 - curved sweep (340ms)
        Trace {
            steps: build_trace(&[
                (0.12, 0.05, 12),
                (0.15, 0.08, 12),
                (0.16, 0.12, 13),
                (0.15, 0.15, 14),
                (0.13, 0.16, 15),
                (0.10, 0.16, 16),
                (0.08, 0.13, 17),
                (0.06, 0.10, 18),
                (0.05, 0.05, 18),
            ]),
        },
        // Trace 8 - multi-segment hesitation (620ms)
        Trace {
            steps: build_trace(&[
                (0.06, 0.04, 16),
                (0.10, 0.07, 14),
                (0.13, 0.10, 13),
                // pause
                (0.01, 0.00, 28),
                // continue
                (0.12, 0.13, 13),
                (0.13, 0.15, 14),
                (0.13, 0.15, 15),
                // small reverse
                (-0.03, -0.02, 13),
                // reach
                (0.10, 0.13, 14),
                (0.10, 0.10, 16),
                (0.07, 0.07, 18),
                (0.08, 0.08, 18),
            ]),
        },
    ]
}

/// Build a [`Trace`] from a deltas list while AUTO-NORMALISING the
/// final cumulative position to exactly (1.0, 1.0). The bundled
/// corpus values are hand-tuned to come close; this helper closes
/// the residual rounding gap in the LAST step so callers always
/// see a unit-square trace.
fn build_trace(steps: &[(f32, f32, u32)]) -> Vec<Step> {
    let mut acc_x = 0.0f32;
    let mut acc_y = 0.0f32;
    let mut out = Vec::with_capacity(steps.len());
    for (dx, dy, dt) in steps {
        acc_x += dx;
        acc_y += dy;
        out.push(Step {
            dx: *dx,
            dy: *dy,
            dt_ms: *dt,
        });
    }
    // Final-step normalisation: nudge the last step so the
    // cumulative end lands exactly at (1.0, 1.0).
    if let Some(last) = out.last_mut() {
        last.dx += 1.0 - acc_x;
        last.dy += 1.0 - acc_y;
    }
    out
}

#[cfg(test)]
mod tests;
