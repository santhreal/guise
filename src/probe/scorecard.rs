//! Oracle scorecard, the shared cross-crate contract for fingerprint
//! divergences (G181, G184, G195, G196, G217).
//!
//! The scorecard takes the differential oracle's raw divergences and maps them
//! onto the shared [`crate::fingerprint::surface`] taxonomy. Every scored entry
//! carries:
//!
//!   * the inventory surface-id (the contract reynard evades, sear detects, and
//!     captchaforge gates against);
//!   * the detector-weight calibrated for that surface's [`Criticality`];
//!   * the benchmark points the divergence costs on a notional fingerprinter
//!     scoreboard;
//!   * the divergence kind (persona-intended vs engine-level) so operators can
//!     prioritize real tells over expected persona-vs-host differences.
//!
//! The schema is versioned and serializable so it can be emitted by `guise bench`
//! (G305), consumed by reynard's CI scorecard regression gate (G307), and
//! compared across runs without prose parsing.

use super::surface_coverage::surface_for_probe;
use super::{DifferentialReport, DivergenceKind, Severity};
use crate::fingerprint::surface::Criticality;
use crate::fingerprint::SurfaceCategory;
use serde::{Deserialize, Serialize};

/// Current scorecard schema version. Bumps when fields change in a breaking way.
pub const SCORECARD_SCHEMA_VERSION: u32 = 1;

/// A fingerprint-surface reference embedded in a scorecard entry.
///
/// Uses the inventory surface-id as the stable key, plus the human-readable
/// category and calibrated criticality. Keeping these together makes the
/// scorecard self-describing for consumers that do not import guise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScorecardSurface {
    /// Inventory surface-id, e.g. `navigator.webdriver`.
    pub surface_id: String,
    /// Surface family (Navigator, WebGl, Canvas, …).
    pub category: SurfaceCategory,
    /// Calibrated criticality from the inventory.
    pub criticality: Criticality,
}

/// One divergence expressed as a scorecard entry with calibrated impact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScorecardEntry {
    /// Shared taxonomy surface this entry is about.
    pub surface: ScorecardSurface,
    /// Catalogue probe name that produced the divergence.
    pub probe_name: String,
    /// Catalogue severity (High/Medium/Low) (the probe's own severity).
    pub severity: Severity,
    /// Calibrated detector weight for this surface.
    pub weight: u16,
    /// Benchmark points the divergence costs on a notional scoreboard.
    pub benchmark_points: u16,
    /// Why it diverged (persona-intended surfaces are deprioritized).
    pub kind: DivergenceKind,
    /// Rendered value from the first browser / baseline.
    pub a_value: String,
    /// Rendered value from the second browser / disguise.
    pub b_value: String,
}

/// A full scorecard for a differential-oracle run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scorecard {
    /// Schema version for cross-crate compatibility.
    pub schema_version: u32,
    /// Label of the baseline browser.
    pub label_a: String,
    /// Label of the candidate / disguise browser.
    pub label_b: String,
    /// Target browser family the catalogue was run against.
    pub browser: String,
    /// Total surfaces compared.
    pub surfaces: usize,
    /// Surfaces where both sides agreed.
    pub agreed: usize,
    /// Surfaces that diverged.
    pub diverged: usize,
    /// Surfaces where at least one side failed to evaluate.
    pub errors: usize,
    /// Sum of weights for all probed surfaces.
    pub total_weight: u32,
    /// Sum of benchmark_points across diverging surfaces.
    pub lost_points: u32,
    /// Scored divergence entries.
    pub entries: Vec<ScorecardEntry>,
}

impl Scorecard {
    /// `true` when no points were lost and there were no evaluation errors.
    pub fn is_clean(&self) -> bool {
        self.lost_points == 0 && self.errors == 0 && self.diverged == 0
    }

    /// Entries sorted by benchmark impact (highest first), the order an operator
    /// should fix them in (G196). Engine-level tells outrank persona-intended
    /// ones at the same point value because they are actionable leaks rather
    /// than expected overrides.
    pub fn prioritized_fixes(&self) -> Vec<&ScorecardEntry> {
        let mut v: Vec<_> = self.entries.iter().collect();
        v.sort_by(|x, y| {
            (
                y.benchmark_points,
                engine_first_rank(x.kind),
                &x.surface.surface_id,
            )
                .cmp(&(
                    x.benchmark_points,
                    engine_first_rank(y.kind),
                    &y.surface.surface_id,
                ))
        });
        v
    }

    /// Human-readable summary, stable and deterministic.
    pub fn summary(&self) -> String {
        format!(
            "{} vs {} ({}): {}/{} surfaces agree, {} diverged, {} errors, {} lost points",
            self.label_a,
            self.label_b,
            self.browser,
            self.agreed,
            self.surfaces,
            self.diverged,
            self.errors,
            self.lost_points
        )
    }
}

fn engine_first_rank(kind: DivergenceKind) -> u8 {
    match kind {
        DivergenceKind::EngineDivergence => 0,
        DivergenceKind::PersonaIntended => 1,
    }
}

/// Calibrated detector weight for a surface, derived from its inventory
/// criticality (G184). The mapping is based on the observed weight real
/// fingerprinters place on these signals:
///
///   * Critical (a binary automation tell (e.g. `navigator.webdriver`)).
///     Detectors treat this as a hard signal; weight 100.
///   * High, heavily-weighted entropy / integrity surfaces (WebGL, plugins,
///     languages, platform, UA). Weight 40.
///   * Medium (contributing signals (vendor, battery, media capabilities)).
///     Weight 10.
///   * Low (corroborating noise (colorDepth, connection.effectiveType)).
///     Weight 2.
///
/// For probes that are not bridged to the inventory, we fall back to the
/// catalogue [`Severity`] with a slightly lower weight to avoid overclaiming.
#[must_use]
pub fn weight_for_surface(criticality: Option<Criticality>, severity: Severity) -> u16 {
    match criticality {
        Some(Criticality::Critical) => 100,
        Some(Criticality::High) => 40,
        Some(Criticality::Medium) => 10,
        Some(Criticality::Low) => 2,
        None => match severity {
            Severity::High => 30,
            Severity::Medium => 8,
            Severity::Low => 1,
        },
    }
}

/// Benchmark points for a divergence equal its weight. A scoreboard starts at
/// zero and loses these points per divergence; this makes the scorecard a
/// direct input to `guise bench` / CI regression gates (G195).
#[must_use]
pub fn benchmark_points_for(weight: u16) -> u16 {
    weight
}

/// Severity auto-tuning from real detector verdicts (G216).
///
/// A detector or WAF reports which surfaces contributed to a block/challenge.
/// The tuner nudges the scorecard weights for those surfaces upward so the next
/// run reflects observed detector reality rather than only the static
/// calibration. This is intentionally conservative: weights can only increase,
/// never decrease, and the multiplier is capped so a single noisy verdict cannot
/// dominate the scorecard.
#[derive(Debug, Clone)]
pub struct SeverityTuner {
    /// Multiplier applied to a surface's weight when a detector reports it
    /// contributed to a block. Default 1.5.
    pub boost: f64,
    /// Hard ceiling for any boosted weight to prevent runaway values.
    pub max_weight: u16,
}

impl Default for SeverityTuner {
    fn default() -> Self {
        Self {
            boost: 1.5,
            max_weight: 250,
        }
    }
}

impl SeverityTuner {
    /// Create a tuner with the default boost (1.5x) and ceiling (250).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adjust `scorecard` in place: for every entry whose surface_id or
    /// probe_name appears in `blocked_surfaces`, increase `weight` and
    /// `benchmark_points` by `boost`, capped at `max_weight`. `lost_points` is
    /// recomputed from the updated entries.
    pub fn tune(&self, scorecard: &mut Scorecard, blocked_surfaces: &[String]) {
        let blocked: std::collections::HashSet<&str> =
            blocked_surfaces.iter().map(|s| s.as_str()).collect();
        let mut lost_points = 0u32;
        for entry in &mut scorecard.entries {
            let is_blocked = blocked.contains(entry.surface.surface_id.as_str())
                || blocked.contains(entry.probe_name.as_str());
            if is_blocked {
                let boosted = (f64::from(entry.weight) * self.boost) as u32;
                let new_weight = boosted.min(u32::from(self.max_weight)).max(1) as u16;
                entry.weight = new_weight;
                entry.benchmark_points = benchmark_points_for(new_weight);
            }
            lost_points += u32::from(entry.benchmark_points);
        }
        scorecard.lost_points = lost_points;
    }

    /// Convenience: tune from a list of surface IDs without requiring the caller
    /// to allocate `String`s.
    pub fn tune_str(&self, scorecard: &mut Scorecard, blocked_surfaces: &[&str]) {
        let owned: Vec<String> = blocked_surfaces.iter().map(|s| (*s).to_string()).collect();
        self.tune(scorecard, &owned);
    }
}

/// Build a scorecard from a differential report, anchoring every divergence to
/// the shared surface taxonomy where possible.
#[must_use]
pub fn scorecard_from_report(
    report: &DifferentialReport,
    browser: crate::fingerprint::UserAgentBrowser,
) -> Scorecard {
    let mut entries = Vec::with_capacity(report.divergences.len());
    let mut total_weight = 0u32;
    let mut lost_points = 0u32;

    // Weigh every surface that was compared, not just divergences, so the
    // scorecard denominator is meaningful. For agreed surfaces we don't emit an
    // entry but we still accumulate total_weight.
    for div in &report.divergences {
        let inv_surface = surface_for_probe(&div.surface);
        let criticality = inv_surface.map(|s| s.criticality);
        let category = inv_surface
            .map(|s| s.category)
            .unwrap_or(SurfaceCategory::Navigator);
        let surface_id = inv_surface
            .map(|s| s.surface.to_string())
            .unwrap_or_else(|| div.surface.clone());

        let weight = weight_for_surface(criticality, div.severity);
        let points = benchmark_points_for(weight);
        total_weight += u32::from(weight);
        lost_points += u32::from(points);

        entries.push(ScorecardEntry {
            surface: ScorecardSurface {
                surface_id,
                category,
                criticality: criticality.unwrap_or(Criticality::Low),
            },
            probe_name: div.surface.clone(),
            severity: div.severity,
            weight,
            benchmark_points: points,
            kind: div.kind,
            a_value: div.a_value.clone(),
            b_value: div.b_value.clone(),
        });
    }

    Scorecard {
        schema_version: SCORECARD_SCHEMA_VERSION,
        label_a: report.label_a.clone(),
        label_b: report.label_b.clone(),
        browser: format!("{browser:?}"),
        surfaces: report.surfaces,
        agreed: report.agreed,
        diverged: report.diverged,
        errors: report.errors,
        total_weight,
        lost_points,
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::UserAgentBrowser;
    use crate::probe::surface_coverage::divergence_kind_for_probe;
    use crate::probe::Divergence;

    fn div(name: &str, sev: Severity) -> Divergence {
        Divergence {
            surface: name.to_string(),
            surface_id: crate::probe::surface_coverage::surface_id_for_probe(name)
                .map(|s| s.to_string()),
            severity: sev,
            kind: divergence_kind_for_probe(name),
            a_value: "a".into(),
            b_value: "b".into(),
        }
    }

    fn rep(divs: Vec<Divergence>) -> DifferentialReport {
        DifferentialReport {
            label_a: "stock".into(),
            label_b: "disguise".into(),
            surfaces: 10,
            agreed: 10 - divs.len(),
            diverged: divs.len(),
            errors: 0,
            divergences: divs,
        }
    }

    #[test]
    fn webdriver_criticality_gives_max_weight_and_points() {
        let d = div("navigator.webdriver", Severity::High);
        let report = rep(vec![d]);
        let sc = scorecard_from_report(&report, UserAgentBrowser::Firefox);
        assert_eq!(sc.entries.len(), 1);
        let e = &sc.entries[0];
        assert_eq!(e.surface.surface_id, "navigator.webdriver");
        assert_eq!(e.surface.criticality, Criticality::Critical);
        assert_eq!(e.weight, 100);
        assert_eq!(e.benchmark_points, 100);
        assert_eq!(sc.lost_points, 100);
    }

    #[test]
    fn webgl_high_surface_gets_high_weight() {
        let d = div("WebGL UNMASKED_VENDOR not SwiftShader", Severity::High);
        let sc = scorecard_from_report(&rep(vec![d]), UserAgentBrowser::Firefox);
        let e = &sc.entries[0];
        assert_eq!(e.surface.surface_id, "webgl.getParameter");
        assert_eq!(e.surface.criticality, Criticality::High);
        assert_eq!(e.weight, 40);
        assert_eq!(e.benchmark_points, 40);
    }

    #[test]
    fn unbridged_probe_falls_back_to_severity_weight() {
        let d = div("window.chrome.runtime exists", Severity::High);
        let sc = scorecard_from_report(&rep(vec![d]), UserAgentBrowser::Firefox);
        let e = &sc.entries[0];
        // Not in inventory bridge → fallback High severity weight.
        assert_eq!(e.weight, 30);
        assert_eq!(e.benchmark_points, 30);
        assert_eq!(e.surface.criticality, Criticality::Low);
    }

    #[test]
    fn clean_scorecard_requires_zero_lost_points_and_errors() {
        let clean = scorecard_from_report(&rep(vec![]), UserAgentBrowser::Firefox);
        assert!(clean.is_clean());
        let dirty = scorecard_from_report(
            &rep(vec![div("navigator.webdriver", Severity::High)]),
            UserAgentBrowser::Firefox,
        );
        assert!(!dirty.is_clean());
    }

    #[test]
    fn serialization_round_trips_cleanly() {
        let sc = scorecard_from_report(
            &rep(vec![
                div("navigator.webdriver", Severity::High),
                div("navigator.plugins.length > 0", Severity::High),
            ]),
            UserAgentBrowser::Firefox,
        );
        let json = serde_json::to_string(&sc).expect("serialize");
        let back: Scorecard = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.schema_version, SCORECARD_SCHEMA_VERSION);
        assert_eq!(back.lost_points, sc.lost_points);
        assert_eq!(back.entries.len(), sc.entries.len());
        assert_eq!(back.entries, sc.entries);
    }

    #[test]
    fn prioritization_orders_by_points_then_engine_kind() {
        let sc = scorecard_from_report(
            &rep(vec![
                // High weight, persona-intended.
                div("navigator.hardwareConcurrency in [2, 16]", Severity::Low),
                // Medium weight, engine divergence.
                div("navigator.plugins.length > 0", Severity::High),
                // Critical, engine divergence.
                div("navigator.webdriver", Severity::High),
            ]),
            UserAgentBrowser::Firefox,
        );
        let ordered: Vec<_> = sc
            .prioritized_fixes()
            .iter()
            .map(|e| e.surface.surface_id.clone())
            .collect();
        assert_eq!(
            ordered,
            vec![
                "navigator.webdriver",
                "navigator.plugins.length",
                "navigator.hardwareConcurrency",
            ]
        );
        // Same critical webdriver entry is the top fix.
        assert_eq!(sc.prioritized_fixes()[0].benchmark_points, 100);
    }

    #[test]
    fn summary_is_stable_and_includes_key_numbers() {
        let sc = scorecard_from_report(
            &rep(vec![div("navigator.webdriver", Severity::High)]),
            UserAgentBrowser::Firefox,
        );
        let s = sc.summary();
        assert!(s.contains("stock vs disguise"));
        assert!(s.contains("1 diverged"));
        assert!(s.contains("100 lost points"));
    }

    #[test]
    fn severity_tuner_boosts_blocked_surface_weight_and_lost_points() {
        let mut sc = scorecard_from_report(
            &rep(vec![
                div("navigator.webdriver", Severity::High),
                div("navigator.plugins.length > 0", Severity::High),
            ]),
            UserAgentBrowser::Firefox,
        );
        let base_webdriver_points = sc.entries[0].benchmark_points;
        let base_plugins_points = sc.entries[1].benchmark_points;
        let tuner = SeverityTuner::new();
        tuner.tune_str(&mut sc, &["navigator.webdriver"]);

        assert!(sc.entries[0].benchmark_points > base_webdriver_points);
        assert_eq!(sc.entries[1].benchmark_points, base_plugins_points);
        assert!(
            sc.lost_points > u32::from(base_webdriver_points + base_plugins_points),
            "lost_points must reflect the boosted weight"
        );
    }

    #[test]
    fn severity_tuner_caps_boosted_weight() {
        let mut sc = scorecard_from_report(
            &rep(vec![div("navigator.webdriver", Severity::High)]),
            UserAgentBrowser::Firefox,
        );
        let tuner = SeverityTuner {
            boost: 100.0,
            max_weight: 200,
        };
        tuner.tune_str(&mut sc, &["navigator.webdriver"]);
        assert_eq!(sc.entries[0].weight, 200);
        assert_eq!(sc.entries[0].benchmark_points, 200);
    }

    #[test]
    fn weight_table_matches_criticality_calibration() {
        // G184 (the mapping between inventory criticality and weight is pinned).
        assert_eq!(
            weight_for_surface(Some(Criticality::Critical), Severity::Low),
            100
        );
        assert_eq!(
            weight_for_surface(Some(Criticality::High), Severity::Low),
            40
        );
        assert_eq!(
            weight_for_surface(Some(Criticality::Medium), Severity::Low),
            10
        );
        assert_eq!(weight_for_surface(Some(Criticality::Low), Severity::Low), 2);
        // Severity fallback when no inventory bridge.
        assert_eq!(weight_for_surface(None, Severity::High), 30);
        assert_eq!(weight_for_surface(None, Severity::Medium), 8);
        assert_eq!(weight_for_surface(None, Severity::Low), 1);
    }
}
