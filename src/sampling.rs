//! Shared random sampling primitives for stealth timing models.

pub use guise_choice::{seed_from_u64, seeded_rng, Seed};

use rand::Rng;

/// A deterministic persona-level seed.
///
/// One `RngSeed` flows through rotation, profile selection, behavioral sampling,
/// and fingerprint derivation. Storing the seed lets an operator reproduce the
/// exact same persona, timing stream, and trace for incident triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RngSeed {
    /// Raw 32-byte seed fed into the deterministic RNG.
    pub bytes: Seed,
}

impl RngSeed {
    /// Build a seed from a small integer identifier.
    #[must_use]
    pub fn from_u64(seed: u64) -> Self {
        Self {
            bytes: seed_from_u64(seed),
        }
    }

    /// Build a seed from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Seed) -> Self {
        Self { bytes }
    }

    /// Deterministically derive a sub-seed for a labelled layer.
    ///
    /// Calling `seed.derive("rotation")` and `seed.derive("behavior")` from the
    /// same parent seed yields two independent but reproducible streams, so one
    /// persona seed can feed every subsystem without cross-correlation.
    #[must_use]
    pub fn derive(&self, label: &str) -> Self {
        let mut state = u64::from_le_bytes([
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5],
            self.bytes[6],
            self.bytes[7],
        ]);
        // Mix the label into the state so different labels diverge.
        for byte in label.bytes() {
            state = splitmix64(state.wrapping_add(u64::from(byte)));
        }
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            state = splitmix64(state);
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        Self { bytes }
    }
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Minimum coefficient of variation (σ/μ) that separates human-shaped timing
/// dispersion from a near-uniform machine cadence.
///
/// This is a single source of truth consumed from BOTH sides of the disguise:
/// the **detector** ([`crate::probe`]'s `classify_timing_cv`) gates a live
/// browser's busy-loop scheduler jitter on it, and the **generator** (the
/// `human` layer's keystroke/pacing timing) is held to the same floor by
/// `keystroke::tests::generated_typing_rhythm_clears_human_cv_floor`. Closing
/// that loop means the rhythm guise *emits* clears the very bar a behavioural
/// classifier (and our own probe) would fail it on. Drawn from behavioural-
/// biometrics literature: human inter-event intervals run CV ≈ 0.15–0.4, while
/// uniform automated schedulers sit near 0.
///
/// The detector half lives in `probe::redteam::classify_timing_cv`, which is
/// gated behind the `browser` feature; without it the only remaining reference
/// is the `human` keystroke test mirror (`#[cfg(test)]`). Hence the dead-code
/// allowance below applies precisely when `browser` is absent, so dropping the
/// probe consumer while `browser` is on still trips the warning.
#[cfg_attr(not(feature = "browser"), allow(dead_code))]
pub(crate) const HUMAN_TIMING_CV_FLOOR: f64 = 0.1;

/// Soft floor between [`HUMAN_TIMING_CV_FLOOR`] and a hard machine tell. A CV in
/// `[CV_DRIFT_FLOOR, HUMAN_TIMING_CV_FLOOR)` is suspiciously low but not provably
/// synthetic (drift); below it is a near-uniform timer (critical). Consumed by
/// the same `browser`-gated `classify_timing_cv`: see [`HUMAN_TIMING_CV_FLOOR`].
#[cfg_attr(not(feature = "browser"), allow(dead_code))]
pub(crate) const CV_DRIFT_FLOOR: f64 = 0.03;

/// Sample a standard normal variate using the Box-Muller transform.
///
/// Consumed by the `human` timing/motion models; in a `human`-less build (e.g.
/// `--features browser` alone) it is legitimately unused.
#[cfg_attr(not(feature = "human"), allow(dead_code))]
pub(crate) fn standard_normal<R: Rng + ?Sized>(rng: &mut R) -> f64 {
    let u1: f64 = rng.gen::<f64>().max(1e-12);
    let u2: f64 = rng.gen::<f64>();
    (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
}

/// Population coefficient of variation (σ/μ) of a sample.
///
/// Returns `None` when the dispersion is undefined: fewer than two points, or a
/// non-positive mean. Used to score whether a generated timing stream (keystroke
/// gaps, pacing intervals) carries human-like dispersion against
/// [`HUMAN_TIMING_CV_FLOOR`], the Rust-side mirror of the JS busy-loop CV the
/// probe computes in the page.
///
/// Consumed only by the `human` keystroke-rhythm realism tests (and this
/// module's own tests) as the Rust-side oracle for the JS probe's math; it has
/// no non-test caller, so it reads as dead code in any `--lib` build regardless
/// of which features are enabled. Gate the allowance on `not(test)` so the
/// suppression holds whenever the test harness isn't compiled.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn coefficient_of_variation(samples: &[f64]) -> Option<f64> {
    if samples.len() < 2 {
        return None;
    }
    let n = samples.len() as f64;
    let mean = samples.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return None;
    }
    let variance = samples
        .iter()
        .map(|x| {
            let d = x - mean;
            d * d
        })
        .sum::<f64>()
        / n;
    Some(variance.sqrt() / mean)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn standard_normal_is_finite_and_centered() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 10_000;
        let samples: Vec<f64> = (0..n).map(|_| standard_normal(&mut rng)).collect();

        assert!(samples.iter().all(|sample| sample.is_finite()));

        let mean = samples.iter().sum::<f64>() / n as f64;
        assert!(mean.abs() < 0.05, "mean too far from zero: {mean}");

        let variance = samples
            .iter()
            .map(|sample| {
                let delta = sample - mean;
                delta * delta
            })
            .sum::<f64>()
            / n as f64;
        assert!(
            (0.90..=1.10).contains(&variance),
            "variance should be near one, got {variance}"
        );
    }

    #[test]
    fn cv_undefined_for_degenerate_samples() {
        assert_eq!(coefficient_of_variation(&[]), None, "empty has no CV");
        assert_eq!(
            coefficient_of_variation(&[5.0]),
            None,
            "single point has no CV"
        );
        assert_eq!(
            coefficient_of_variation(&[0.0, 0.0]),
            None,
            "zero mean makes CV undefined"
        );
    }

    #[test]
    fn cv_zero_for_constant_stream() {
        // A perfectly uniform (machine) cadence has zero dispersion, the tell
        // HUMAN_TIMING_CV_FLOOR is meant to catch.
        let cv = coefficient_of_variation(&[100.0, 100.0, 100.0, 100.0]).unwrap();
        assert!(cv.abs() < 1e-9, "constant stream CV {cv} should be 0");
        assert!(cv < HUMAN_TIMING_CV_FLOOR);
    }

    #[test]
    fn cv_matches_hand_computed_value() {
        // mean = 3, population σ = sqrt(2/3) ≈ 0.8165, CV ≈ 0.2722.
        let cv = coefficient_of_variation(&[2.0, 3.0, 4.0]).unwrap();
        assert!((cv - 0.272_166).abs() < 1e-4, "CV {cv} != hand value");
        assert!(
            cv >= HUMAN_TIMING_CV_FLOOR,
            "spread-out stream clears floor"
        );
    }

    #[allow(clippy::assertions_on_constants)] // contract canary on the timing floors
    #[test]
    fn cv_drift_floor_below_human_floor() {
        assert!(CV_DRIFT_FLOOR < HUMAN_TIMING_CV_FLOOR);
    }

    #[test]
    fn rng_seed_from_u64_is_deterministic() {
        let a = RngSeed::from_u64(42);
        let b = RngSeed::from_u64(42);
        assert_eq!(a, b);
        assert_ne!(a.bytes, RngSeed::from_u64(43).bytes);
    }

    #[test]
    fn rng_seed_derive_is_deterministic_and_label_dependent() {
        let parent = RngSeed::from_u64(7);
        let a = parent.derive("rotation");
        let b = parent.derive("rotation");
        let c = parent.derive("behavior");
        assert_eq!(a, b);
        assert_ne!(
            a.bytes, c.bytes,
            "different labels must derive different seeds"
        );
    }

    #[test]
    fn seeded_rng_from_seed_reproduces_samples() {
        let seed = RngSeed::from_u64(99);
        let mut rng_a = seeded_rng(&seed.bytes);
        let mut rng_b = seeded_rng(&seed.bytes);
        assert_eq!(rng_a.gen::<u64>(), rng_b.gen::<u64>());
    }

    #[test]
    fn derive_produces_independent_streams() {
        let parent = RngSeed::from_u64(5);
        let mut rng_a = seeded_rng(&parent.derive("a").bytes);
        let mut rng_b = seeded_rng(&parent.derive("b").bytes);
        let samples_a: Vec<u64> = (0..64).map(|_| rng_a.gen()).collect();
        let samples_b: Vec<u64> = (0..64).map(|_| rng_b.gen()).collect();
        assert_ne!(samples_a, samples_b);
    }
}
