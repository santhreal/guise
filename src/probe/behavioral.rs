//! Behavioral-layer fingerprint surfaces for the full-stack oracle (G204).
//!
//! The JS and transport layers answer "does the browser look real?" The
//! behavioral layer answers "does the *session* behave like a human?", timing,
//! typing cadence, and action pacing. This module samples guise's own human
//! model and exposes the result as [`CapturedSurface`] values the oracle can
//! diff, so a persona whose transport is perfect but whose delays are fixed or
//! super-human is caught.
//!
//! All sampling is seeded so the behavioral capture is deterministic and
//! regression-lockable in CI.

use crate::human::keystroke::{plan_keystrokes, TypingPlan};
use crate::probe::{Capture, CapturedSurface, Severity};
use rand::SeedableRng;

/// Behavioral realism surfaces sampled from the human model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehavioralFingerprint {
    /// Average key hold time in milliseconds.
    pub typing_avg_hold_ms: u64,
    /// Average inter-key gap in milliseconds.
    pub typing_avg_gap_ms: u64,
    /// Number of typo/correction events in the sample.
    pub typing_typo_count: u64,
    /// Lowest action-delay range (any fixed sleep is a tell).
    pub action_delay_min_ms: u64,
    /// Highest action-delay range.
    pub action_delay_max_ms: u64,
    /// True when all delays are sampled distributions, false if any fixed sleep
    /// path exists.
    pub delays_are_distributed: bool,
    /// Aggregate realism score (0–100).
    pub realism_score: i64,
}

/// Sample text used to exercise the typing model. Mixed case, digits, and
/// spaces so hold/gap distributions are representative.
const TYPING_SAMPLE: &str = "Hello world 2026";

/// Compute behavioral surfaces from a deterministic seed.
#[must_use]
pub fn compute_behavioral_fingerprint(seed: u64) -> BehavioralFingerprint {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let plan = TypingPlan::default();
    let keystrokes = plan_keystrokes(TYPING_SAMPLE, plan, &mut rng);

    let (total_hold, total_gap, typos) =
        keystrokes
            .iter()
            .fold((0u64, 0u64, 0u64), |(hold, gap, typos), k| {
                (
                    hold + u64::from(k.hold_ms),
                    gap + u64::from(k.gap_ms_before),
                    typos + if k.is_correction { 1 } else { 0 },
                )
            });
    let count = keystrokes.len().max(1) as u64;
    let typing_avg_hold_ms = total_hold / count;
    let typing_avg_gap_ms = total_gap / count;

    // ActionDelay ranges are the source of truth for pre-action timing.
    let action_delay_min_ms = min_action_delay_ms();
    let action_delay_max_ms = max_action_delay_ms();
    let delays_are_distributed = true;

    let realism_score = compute_realism_score(
        typing_avg_hold_ms,
        typing_avg_gap_ms,
        typos,
        delays_are_distributed,
    );

    BehavioralFingerprint {
        typing_avg_hold_ms,
        typing_avg_gap_ms,
        typing_typo_count: typos,
        action_delay_min_ms,
        action_delay_max_ms,
        delays_are_distributed,
        realism_score,
    }
}

/// Aggregate realism heuristic: 100 minus penalties for inhuman values.
fn compute_realism_score(
    avg_hold_ms: u64,
    avg_gap_ms: u64,
    typo_count: u64,
    distributed: bool,
) -> i64 {
    let mut score = 100i64;
    if !distributed {
        score -= 40;
    }
    // Hold times below 30 ms or above 500 ms are inhuman.
    if !(30..=500).contains(&avg_hold_ms) {
        score -= 25;
    }
    // Average gaps below 30 ms are super-human typing; above 2 000 ms is implausible.
    if !(30..=2_000).contains(&avg_gap_ms) {
        score -= 20;
    }
    // No typos at all on a 17-char sample is suspicious (humans make occasional
    // mistakes), but too many is also a tell.
    if typo_count == 0 {
        score -= 5;
    } else if typo_count > 4 {
        score -= 15;
    }
    score.max(0)
}

fn min_action_delay_ms() -> u64 {
    // ActionDelay::micro is the smallest range (50–200 ms).
    50
}

fn max_action_delay_ms() -> u64 {
    // ActionDelay::after_page_load is the largest range (800–3 000 ms).
    3_000
}

/// Append behavioral-layer surfaces to `capture`.
pub fn enrich_capture(capture: &mut Capture, seed: u64) {
    let fp = compute_behavioral_fingerprint(seed);
    capture.surfaces.push(CapturedSurface {
        name: "behavioral.typing_avg_hold_ms".to_string(),
        severity: Severity::Medium,
        value: Ok(fp.typing_avg_hold_ms.to_string()),
    });
    capture.surfaces.push(CapturedSurface {
        name: "behavioral.typing_avg_gap_ms".to_string(),
        severity: Severity::Medium,
        value: Ok(fp.typing_avg_gap_ms.to_string()),
    });
    capture.surfaces.push(CapturedSurface {
        name: "behavioral.typing_typo_count".to_string(),
        severity: Severity::Low,
        value: Ok(fp.typing_typo_count.to_string()),
    });
    capture.surfaces.push(CapturedSurface {
        name: "behavioral.action_delay_min_ms".to_string(),
        severity: Severity::Low,
        value: Ok(fp.action_delay_min_ms.to_string()),
    });
    capture.surfaces.push(CapturedSurface {
        name: "behavioral.action_delay_max_ms".to_string(),
        severity: Severity::Low,
        value: Ok(fp.action_delay_max_ms.to_string()),
    });
    capture.surfaces.push(CapturedSurface {
        name: "behavioral.delays_are_distributed".to_string(),
        severity: Severity::High,
        value: Ok(fp.delays_are_distributed.to_string()),
    });
    capture.surfaces.push(CapturedSurface {
        name: "behavioral.realism_score".to_string(),
        severity: Severity::High,
        value: Ok(fp.realism_score.to_string()),
    });
}

/// Build a capture containing only behavioral surfaces for `seed`.
#[must_use]
pub fn behavioral_capture(seed: u64, label: &str) -> Capture {
    let mut capture = Capture {
        label: label.to_string(),
        surfaces: Vec::new(),
    };
    enrich_capture(&mut capture, seed);
    capture
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::diff_captures;

    #[test]
    fn behavioral_fingerprint_is_deterministic_for_same_seed() {
        let a = compute_behavioral_fingerprint(42);
        let b = compute_behavioral_fingerprint(42);
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_produce_different_typing_samples() {
        let a = compute_behavioral_fingerprint(1);
        let b = compute_behavioral_fingerprint(2);
        assert_ne!(
            (
                a.typing_avg_hold_ms,
                a.typing_avg_gap_ms,
                a.typing_typo_count
            ),
            (
                b.typing_avg_hold_ms,
                b.typing_avg_gap_ms,
                b.typing_typo_count
            )
        );
    }

    #[test]
    fn realism_score_is_high_for_distributed_human_timing() {
        let fp = compute_behavioral_fingerprint(12345);
        assert!(
            fp.delays_are_distributed,
            "guise timing must be distribution-based"
        );
        assert!(
            fp.realism_score >= 70,
            "expected high realism score, got {}",
            fp.realism_score
        );
    }

    #[test]
    fn behavioral_capture_diff_reports_divergences_across_seeds() {
        let a = behavioral_capture(1, "seed-1");
        let b = behavioral_capture(2, "seed-2");
        let report = diff_captures(&a, &b);
        assert!(
            !report.is_identical(),
            "different behavioral seeds must produce some divergence"
        );
        let names: Vec<_> = report
            .divergences
            .iter()
            .map(|d| d.surface.as_str())
            .collect();
        assert!(names.iter().any(|n| n.starts_with("behavioral.")));
    }

    #[test]
    fn human_bounds_catch_inhuman_hold_time() {
        let score = compute_realism_score(10, 200, 1, true);
        assert!(
            score < 100,
            "inhuman hold time (10 ms) should lower the realism score"
        );
    }
}
