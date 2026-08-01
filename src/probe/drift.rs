//! Production drift detector + auto-bisect for the full-stack oracle (G207, G208).
//!
//! A long-running persona should not silently start leaking new fingerprint tells.
//! [`DriftDetector`] compares a *baseline* full-stack capture against a *current*
//! full-stack capture and reports only the **new** divergences, surfaces that
//! were clean in the baseline but now disagree with the reference browser. This
//! is the signal that should page an operator: a detector update just found a
//! fresh tell, a profile rotation landed a bad combination, or a patch regressed.
//!
//! The companion [`BisectReport`] attributes new divergences to the layer that
//! changed (JS / transport / behavioral) and, when a [`PersonaContext`] is
//! attached to each snapshot, to the persona field or engine patch most likely
//! responsible.

use super::surface_coverage::{surface_id_for_probe, SPOOF_SURFACE_LINKS};
use super::{
    full_stack_compare, Capture, Divergence, DivergenceKind, FullStackReport, Scorecard, Severity,
};
use crate::fingerprint::{
    profile_os_network_stack, profile_to_overrides, profile_user_agent, StealthProfile,
    UserAgentBrowser,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

/// Human-readable context attached to a snapshot so drift can be attributed to a
/// persona/seed/profile rather than to an opaque capture label.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersonaContext {
    /// Display label for the snapshot (often the UA or a host name).
    pub label: String,
    /// Canonical stealth profile name.
    pub profile_name: String,
    /// Seed that generated this persona, if any.
    pub seed: u64,
    /// User-Agent string used by the persona.
    pub user_agent: String,
    /// `navigator.platform` value used by the persona.
    pub platform: String,
    /// TLS impersonation profile identifier (empty when the `http` feature is off).
    pub tls_profile: String,
    /// OS-level network stack descriptor used for TCP/JA4T shaping.
    pub os_stack: String,
}

impl PersonaContext {
    /// Build a context from a built-in profile and optional seed.
    #[must_use]
    pub fn from_profile(profile: StealthProfile, seed: Option<u64>) -> Self {
        let ov = profile_to_overrides(&profile);
        let os_stack = format!("{:?}", profile_os_network_stack(profile));
        Self {
            label: profile_user_agent(profile).to_string(),
            profile_name: format!("{profile:?}"),
            seed: seed.unwrap_or(0),
            user_agent: ov.user_agent,
            platform: ov.platform,
            tls_profile: String::new(),
            os_stack,
        }
    }

    /// Set the TLS profile string (callers using the `http` feature can populate
    /// this from [`crate::fingerprint::ProfileBundle::tls`]).
    #[must_use]
    pub fn with_tls_profile(mut self, tls_profile: String) -> Self {
        self.tls_profile = tls_profile;
        self
    }
}

/// One full-stack measurement at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftSnapshot {
    /// UNIX epoch seconds when the snapshot was taken.
    pub captured_at_secs: u64,
    /// JavaScript surface capture.
    pub js: Capture,
    /// Transport-layer (JA3/JA4/H2/TCP) capture.
    pub transport: Capture,
    /// Behavioral-layer (timing/typing/mouse) capture.
    pub behavioral: Capture,
    /// Optional persona context for attribution.
    pub context: Option<PersonaContext>,
}

impl DriftSnapshot {
    /// Build a snapshot with the current wall-clock time.
    #[must_use]
    pub fn new(
        js: Capture,
        transport: Capture,
        behavioral: Capture,
        context: Option<PersonaContext>,
    ) -> Self {
        Self {
            captured_at_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            js,
            transport,
            behavioral,
            context,
        }
    }
}

/// Logical layer that a divergence belongs to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer {
    /// JavaScript / DOM / API surface layer.
    Js,
    /// TLS / JA3 / JA4 / H2 / TCP shape layer.
    Transport,
    /// Human-behavior timing / typing / mouse layer.
    Behavioral,
}

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Layer::Js => write!(f, "js"),
            Layer::Transport => write!(f, "transport"),
            Layer::Behavioral => write!(f, "behavioral"),
        }
    }
}

/// Auto-bisect result for a drift event: what changed and where to look first.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BisectReport {
    /// Layers that acquired at least one new divergence.
    pub changed_layers: Vec<Layer>,
    /// Persona override fields suspected based on the new divergence surfaces
    /// (empty when the divergences are not on persona-overridden surfaces).
    pub suspect_persona_fields: Vec<String>,
    /// Surfaces classified as engine-level tells that should be investigated as a
    /// patch or engine regression.
    pub suspect_engine_surfaces: Vec<String>,
    /// Differences in the attached [`PersonaContext`] between baseline and current.
    pub context_delta: Vec<String>,
    /// Single-line primary suspect for operators.
    pub primary_suspect: String,
}

impl BisectReport {
    #[allow(dead_code)] // constructor kept for report-shape completeness
    fn empty() -> Self {
        Self {
            changed_layers: Vec::new(),
            suspect_persona_fields: Vec::new(),
            suspect_engine_surfaces: Vec::new(),
            context_delta: Vec::new(),
            primary_suspect: "none".to_string(),
        }
    }
}

/// Result of a drift-detection pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvent {
    /// Baseline capture label.
    pub baseline_label: String,
    /// Current capture label.
    pub current_label: String,
    /// Divergences that are present now but were not present (or looked different)
    /// in the baseline.
    pub new_divergences: Vec<Divergence>,
    /// Divergences that were present in the baseline but are now clean.
    pub recovered_divergences: Vec<Divergence>,
    /// Divergences present in both snapshots with the same candidate value.
    pub still_diverging: Vec<Divergence>,
    /// Scorecard for the current snapshot.
    pub scorecard: Scorecard,
    /// Bisect attribution report.
    pub bisect: BisectReport,
    /// Whether any new divergence meets or exceeds the configured threshold.
    pub alerted: bool,
}

impl DriftEvent {
    /// One-line human summary.
    pub fn summary(&self) -> String {
        format!(
            "drift {} -> {}: {} new, {} recovered, {} still diverging, {} lost points, alert={}",
            self.baseline_label,
            self.current_label,
            self.new_divergences.len(),
            self.recovered_divergences.len(),
            self.still_diverging.len(),
            self.scorecard.lost_points,
            self.alerted
        )
    }

    /// `true` when there are no new divergences and no evaluation errors in the
    /// current snapshot.
    pub fn is_clean(&self) -> bool {
        self.new_divergences.is_empty() && self.scorecard.errors == 0
    }
}

/// Detects new fingerprint drift by comparing a *baseline* snapshot and a
/// *current* snapshot against the same stock-FF reference snapshot.
#[derive(Debug, Clone)]
pub struct DriftDetector {
    reference: DriftSnapshot,
    browser: UserAgentBrowser,
    alert_threshold: Severity,
}

impl DriftDetector {
    /// Create a detector anchored to a known-good `reference` capture. Both
    /// `baseline` and `current` snapshots passed to [`detect`](Self::detect) will
    /// be compared against this reference so new vs recovered drift can be told
    /// apart.
    #[must_use]
    pub fn new(reference: DriftSnapshot, browser: UserAgentBrowser) -> Self {
        Self {
            reference,
            browser,
            alert_threshold: Severity::High,
        }
    }

    /// Set the minimum severity that triggers an alert.
    #[must_use]
    pub fn with_alert_threshold(mut self, threshold: Severity) -> Self {
        self.alert_threshold = threshold;
        self
    }

    /// Compare `baseline` to `current` (both against the stored reference) and
    /// return a [`DriftEvent`].
    ///
    /// * new divergences (clean in baseline, drifted in current).
    /// * recovered divergences (drifted in baseline, clean in current).
    /// * still diverging (drifted in both with the same candidate value).
    pub fn detect(&self, baseline: &DriftSnapshot, current: &DriftSnapshot) -> DriftEvent {
        let baseline_report = full_stack_compare(
            &self.reference.js,
            &self.reference.transport,
            &self.reference.behavioral,
            &baseline.js,
            &baseline.transport,
            &baseline.behavioral,
        );
        let current_report = full_stack_compare(
            &self.reference.js,
            &self.reference.transport,
            &self.reference.behavioral,
            &current.js,
            &current.transport,
            &current.behavioral,
        );

        // Per-layer classification: new/recovered/still.
        let js_sets = diff_sets(
            &baseline_report.js.divergences,
            &current_report.js.divergences,
        );
        let transport_sets = diff_sets(
            &baseline_report.transport.divergences,
            &current_report.transport.divergences,
        );
        let behavioral_sets = diff_sets(
            &baseline_report.behavioral.divergences,
            &current_report.behavioral.divergences,
        );

        let mut new_divergences = Vec::new();
        new_divergences.extend(js_sets.new);
        new_divergences.extend(transport_sets.new);
        new_divergences.extend(behavioral_sets.new);

        let mut recovered_divergences = Vec::new();
        recovered_divergences.extend(js_sets.recovered);
        recovered_divergences.extend(transport_sets.recovered);
        recovered_divergences.extend(behavioral_sets.recovered);

        let mut still_diverging = Vec::new();
        still_diverging.extend(js_sets.still);
        still_diverging.extend(transport_sets.still);
        still_diverging.extend(behavioral_sets.still);

        sort_divergences(&mut new_divergences);
        sort_divergences(&mut recovered_divergences);
        sort_divergences(&mut still_diverging);

        let scorecard = current_report.combined_scorecard(self.browser);
        let bisect = bisect(
            &new_divergences,
            &current_report,
            baseline.context.as_ref(),
            current.context.as_ref(),
        );

        let alerted = new_divergences
            .iter()
            .any(|d| severity_meets(d.severity, self.alert_threshold));

        DriftEvent {
            baseline_label: baseline.js.label.clone(),
            current_label: current.js.label.clone(),
            new_divergences,
            recovered_divergences,
            still_diverging,
            scorecard,
            bisect,
            alerted,
        }
    }
}

struct DiffSets {
    new: Vec<Divergence>,
    recovered: Vec<Divergence>,
    still: Vec<Divergence>,
}

fn diff_sets(baseline: &[Divergence], current: &[Divergence]) -> DiffSets {
    let baseline_keys: BTreeSet<(&str, &str)> = baseline.iter().map(divergence_key).collect();
    let current_keys: BTreeSet<(&str, &str)> = current.iter().map(divergence_key).collect();

    let mut new = Vec::new();
    let mut still = Vec::new();
    for d in current {
        let key = divergence_key(d);
        if baseline_keys.contains(&key) {
            still.push(d.clone());
        } else {
            new.push(d.clone());
        }
    }

    let mut recovered = Vec::new();
    for d in baseline {
        if !current_keys.contains(&divergence_key(d)) {
            recovered.push(d.clone());
        }
    }

    DiffSets {
        new,
        recovered,
        still,
    }
}

fn divergence_key(d: &Divergence) -> (&str, &str) {
    (d.surface.as_str(), d.b_value.as_str())
}

fn sort_divergences(divs: &mut [Divergence]) {
    divs.sort_by(|x, y| {
        severity_rank(y.severity)
            .cmp(&severity_rank(x.severity))
            .then(x.surface.cmp(&y.surface))
    });
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
    }
}

fn severity_meets(actual: Severity, threshold: Severity) -> bool {
    severity_rank(actual) >= severity_rank(threshold)
}

fn layer_for_surface(name: &str) -> Layer {
    if name.starts_with("transport.") {
        Layer::Transport
    } else if name.starts_with("behavioral.") {
        Layer::Behavioral
    } else {
        Layer::Js
    }
}

fn bisect(
    new_divergences: &[Divergence],
    report: &FullStackReport,
    baseline_ctx: Option<&PersonaContext>,
    current_ctx: Option<&PersonaContext>,
) -> BisectReport {
    let context_delta = context_delta(baseline_ctx, current_ctx);
    if new_divergences.is_empty() {
        let primary_suspect = if context_delta.is_empty() {
            "none".to_string()
        } else {
            "persona rotation / profile change".to_string()
        };
        return BisectReport {
            changed_layers: Vec::new(),
            suspect_persona_fields: Vec::new(),
            suspect_engine_surfaces: Vec::new(),
            context_delta,
            primary_suspect,
        };
    }

    let mut layers = BTreeSet::new();
    let mut persona_fields = BTreeSet::new();
    let mut engine_surfaces = BTreeSet::new();

    for d in new_divergences {
        layers.insert(layer_for_surface(&d.surface));
        if d.kind == DivergenceKind::EngineDivergence {
            engine_surfaces.insert(d.surface.clone());
        }
        if let Some(surface_id) = surface_id_for_probe(&d.surface) {
            for link in SPOOF_SURFACE_LINKS {
                if link.surface == surface_id {
                    persona_fields.insert(link.field.to_string());
                }
            }
        }
    }

    // Transport-only new divergences are strong evidence the TLS/TCP profile changed.
    if report.transport.diverged > 0 && report.js.diverged == 0 && report.behavioral.diverged == 0 {
        layers.insert(Layer::Transport);
    }

    let primary_suspect = if !context_delta.is_empty() {
        "persona rotation / profile change".to_string()
    } else if !engine_surfaces.is_empty() {
        "engine patch / browser regression".to_string()
    } else if !persona_fields.is_empty() {
        "persona override field drift".to_string()
    } else {
        "unknown layer drift".to_string()
    };

    BisectReport {
        changed_layers: layers.into_iter().collect(),
        suspect_persona_fields: persona_fields.into_iter().collect(),
        suspect_engine_surfaces: engine_surfaces.into_iter().collect(),
        context_delta,
        primary_suspect,
    }
}

fn context_delta(
    baseline_ctx: Option<&PersonaContext>,
    current_ctx: Option<&PersonaContext>,
) -> Vec<String> {
    let (Some(b), Some(c)) = (baseline_ctx, current_ctx) else {
        return Vec::new();
    };

    let mut deltas = Vec::new();
    if b.profile_name != c.profile_name {
        deltas.push(format!("profile: {} -> {}", b.profile_name, c.profile_name));
    }
    if b.user_agent != c.user_agent {
        deltas.push("user_agent changed".to_string());
    }
    if b.platform != c.platform {
        deltas.push(format!("platform: {} -> {}", b.platform, c.platform));
    }
    if b.tls_profile != c.tls_profile && !(b.tls_profile.is_empty() && c.tls_profile.is_empty()) {
        deltas.push("tls_profile changed".to_string());
    }
    if b.os_stack != c.os_stack {
        deltas.push("os_stack changed".to_string());
    }
    if b.seed != c.seed {
        deltas.push(format!("seed: {} -> {}", b.seed, c.seed));
    }
    deltas
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::CapturedSurface;

    fn surface(name: &str, sev: Severity, value: &str) -> CapturedSurface {
        CapturedSurface {
            name: name.to_string(),
            severity: sev,
            value: Ok(value.to_string()),
        }
    }

    fn cap(label: &str, surfaces: Vec<(&str, Severity, &str)>) -> Capture {
        Capture {
            label: label.to_string(),
            surfaces: surfaces
                .into_iter()
                .map(|(n, s, v)| surface(n, s, v))
                .collect(),
        }
    }

    fn snapshot(
        label: &str,
        js: Vec<(&str, Severity, &str)>,
        transport: Vec<(&str, Severity, &str)>,
        behavioral: Vec<(&str, Severity, &str)>,
    ) -> DriftSnapshot {
        DriftSnapshot::new(
            cap(label, js),
            cap(label, transport),
            cap(label, behavioral),
            None,
        )
    }

    fn detector() -> DriftDetector {
        let reference = snapshot(
            "reference",
            vec![
                ("navigator.webdriver", Severity::High, "false"),
                ("screen.colorDepth", Severity::Low, "24"),
                ("navigator.plugins.length > 0", Severity::High, "2"),
                (
                    "navigator.hardwareConcurrency in [2, 16]",
                    Severity::Low,
                    "8",
                ),
            ],
            vec![("transport.ja4", Severity::High, "abc")],
            vec![("behavioral.realism_score", Severity::High, "95")],
        );
        DriftDetector::new(reference, UserAgentBrowser::Firefox)
    }

    #[test]
    fn identical_snapshots_produce_no_drift() {
        // Use the detector's own reference as both baseline and current so the
        // surface sets match exactly and there are no evaluation errors.
        let reference = detector().reference.clone();
        let event = detector().detect(&reference, &reference);
        assert!(event.is_clean());
        assert!(!event.alerted);
        assert!(event.new_divergences.is_empty());
        assert!(event.recovered_divergences.is_empty());
        assert!(event.still_diverging.is_empty());
    }

    #[test]
    fn new_high_severity_divergence_triggers_alert() {
        let baseline = snapshot(
            "baseline",
            vec![("navigator.webdriver", Severity::High, "false")],
            vec![],
            vec![],
        );
        let current = snapshot(
            "current",
            vec![("navigator.webdriver", Severity::High, "true")],
            vec![],
            vec![],
        );
        let event = detector().detect(&baseline, &current);
        assert!(event.alerted);
        assert_eq!(event.new_divergences.len(), 1);
        assert_eq!(event.new_divergences[0].surface, "navigator.webdriver");
        assert!(event.recovered_divergences.is_empty());
    }

    #[test]
    fn new_low_severity_divergence_does_not_alert_when_threshold_is_high() {
        let baseline = snapshot(
            "baseline",
            vec![("screen.colorDepth", Severity::Low, "24")],
            vec![],
            vec![],
        );
        let current = snapshot(
            "current",
            vec![("screen.colorDepth", Severity::Low, "30")],
            vec![],
            vec![],
        );
        let event = detector().detect(&baseline, &current);
        assert!(!event.alerted);
        assert_eq!(event.new_divergences.len(), 1);
    }

    #[test]
    fn alert_threshold_can_be_lowered_to_medium() {
        let baseline = snapshot("baseline", vec![], vec![], vec![]);
        let current = snapshot(
            "current",
            vec![("navigator.plugins.length > 0", Severity::Medium, "0")],
            vec![],
            vec![],
        );
        let event = detector()
            .with_alert_threshold(Severity::Medium)
            .detect(&baseline, &current);
        assert!(event.alerted);
    }

    #[test]
    fn recovered_divergence_is_reported_but_not_alerted() {
        let baseline = snapshot(
            "baseline",
            vec![("navigator.webdriver", Severity::High, "true")],
            vec![],
            vec![],
        );
        let current = snapshot(
            "current",
            vec![("navigator.webdriver", Severity::High, "false")],
            vec![],
            vec![],
        );
        let event = detector().detect(&baseline, &current);
        assert!(!event.alerted);
        assert_eq!(event.recovered_divergences.len(), 1);
        assert!(event.new_divergences.is_empty());
    }

    #[test]
    fn still_diverging_same_value_is_not_new() {
        let baseline = snapshot(
            "baseline",
            vec![("navigator.webdriver", Severity::High, "true")],
            vec![],
            vec![],
        );
        let current = snapshot(
            "current",
            vec![("navigator.webdriver", Severity::High, "true")],
            vec![],
            vec![],
        );
        let event = detector().detect(&baseline, &current);
        assert!(!event.alerted);
        assert!(event.new_divergences.is_empty());
        assert_eq!(event.still_diverging.len(), 1);
    }

    #[test]
    fn new_divergence_with_same_surface_but_different_value_is_new() {
        let baseline = snapshot(
            "baseline",
            vec![("navigator.webdriver", Severity::High, "true")],
            vec![],
            vec![],
        );
        let current = snapshot(
            "current",
            vec![("navigator.webdriver", Severity::High, "undefined")],
            vec![],
            vec![],
        );
        let event = detector().detect(&baseline, &current);
        assert!(event.alerted);
        assert_eq!(event.new_divergences.len(), 1);
        assert_eq!(event.still_diverging.len(), 0);
        assert_eq!(event.recovered_divergences.len(), 1);
    }

    #[test]
    fn bisect_attributes_transport_layer() {
        let baseline = snapshot(
            "baseline",
            vec![],
            vec![("transport.ja4", Severity::High, "abc")],
            vec![],
        );
        let current = snapshot(
            "current",
            vec![],
            vec![("transport.ja4", Severity::High, "changed")],
            vec![],
        );
        let event = detector().detect(&baseline, &current);
        assert!(event.bisect.changed_layers.contains(&Layer::Transport));
        assert!(!event.bisect.changed_layers.contains(&Layer::Js));
    }

    #[test]
    fn bisect_attributes_behavioral_layer() {
        let baseline = snapshot(
            "baseline",
            vec![],
            vec![],
            vec![("behavioral.realism_score", Severity::High, "95")],
        );
        let current = snapshot(
            "current",
            vec![],
            vec![],
            vec![("behavioral.realism_score", Severity::High, "30")],
        );
        let event = detector().detect(&baseline, &current);
        assert!(event.bisect.changed_layers.contains(&Layer::Behavioral));
    }

    #[test]
    fn bisect_maps_persona_override_surface_to_field() {
        let baseline = snapshot(
            "baseline",
            vec![(
                "navigator.hardwareConcurrency in [2, 16]",
                Severity::Low,
                "8",
            )],
            vec![],
            vec![],
        );
        let current = snapshot(
            "current",
            vec![(
                "navigator.hardwareConcurrency in [2, 16]",
                Severity::Low,
                "128",
            )],
            vec![],
            vec![],
        );
        let event = detector().detect(&baseline, &current);
        assert!(
            event
                .bisect
                .suspect_persona_fields
                .contains(&"ProfileOverrides::hardware_concurrency".to_string()),
            "expected hardwareConcurrency field in {:?}",
            event.bisect.suspect_persona_fields
        );
    }

    #[test]
    fn bisect_lists_engine_surface_for_webdriver() {
        let baseline = snapshot(
            "baseline",
            vec![("navigator.webdriver", Severity::High, "false")],
            vec![],
            vec![],
        );
        let current = snapshot(
            "current",
            vec![("navigator.webdriver", Severity::High, "true")],
            vec![],
            vec![],
        );
        let event = detector().detect(&baseline, &current);
        assert!(!event.bisect.suspect_engine_surfaces.is_empty());
        assert!(event
            .bisect
            .suspect_engine_surfaces
            .contains(&"navigator.webdriver".to_string()));
    }

    #[test]
    fn context_delta_reports_rotation() {
        let baseline = DriftSnapshot::new(
            cap("baseline", vec![]),
            cap("baseline", vec![]),
            cap("baseline", vec![]),
            Some(PersonaContext {
                label: "a".into(),
                profile_name: "FirefoxLinux".into(),
                seed: 1,
                user_agent: "ua-a".into(),
                platform: "Linux x86_64".into(),
                tls_profile: String::new(),
                os_stack: "Linux".into(),
            }),
        );
        let current = DriftSnapshot::new(
            cap("current", vec![]),
            cap("current", vec![]),
            cap("current", vec![]),
            Some(PersonaContext {
                label: "b".into(),
                profile_name: "ChromeWindowsStable".into(),
                seed: 2,
                user_agent: "ua-b".into(),
                platform: "Win32".into(),
                tls_profile: String::new(),
                os_stack: "Windows".into(),
            }),
        );
        let event = detector().detect(&baseline, &current);
        assert!(!event.bisect.context_delta.is_empty());
        assert!(event
            .bisect
            .context_delta
            .iter()
            .any(|d| d.contains("profile:")));
        assert!(event
            .bisect
            .context_delta
            .iter()
            .any(|d| d.contains("platform:")));
    }

    #[test]
    fn primary_suspect_is_persona_change_when_context_deltas_exist() {
        let baseline = DriftSnapshot::new(
            cap("baseline", vec![]),
            cap("baseline", vec![]),
            cap("baseline", vec![]),
            Some(PersonaContext::from_profile(
                StealthProfile::FirefoxLinux,
                Some(1),
            )),
        );
        let current = DriftSnapshot::new(
            cap("current", vec![]),
            cap("current", vec![]),
            cap("current", vec![]),
            Some(PersonaContext::from_profile(
                StealthProfile::ChromeWindowsStable,
                Some(2),
            )),
        );
        let event = detector().detect(&baseline, &current);
        assert_eq!(
            event.bisect.primary_suspect,
            "persona rotation / profile change"
        );
    }

    #[test]
    fn scorecard_is_generated_from_current_snapshot() {
        let baseline = snapshot("baseline", vec![], vec![], vec![]);
        let current = snapshot(
            "current",
            vec![("navigator.webdriver", Severity::High, "true")],
            vec![],
            vec![],
        );
        let event = detector().detect(&baseline, &current);
        assert!(!event.scorecard.is_clean());
        assert!(event.scorecard.lost_points > 0);
    }

    #[test]
    fn full_stack_report_layers_are_all_considered() {
        let reference = snapshot(
            "reference",
            vec![("x", Severity::High, "good")],
            vec![("transport.ja4", Severity::High, "abc")],
            vec![("behavioral.realism_score", Severity::High, "95")],
        );
        let baseline = snapshot("baseline", vec![], vec![], vec![]);
        let current = snapshot(
            "current",
            vec![("x", Severity::High, "bad")],
            vec![("transport.ja4", Severity::High, "bad")],
            vec![("behavioral.realism_score", Severity::High, "bad")],
        );
        let detector = DriftDetector::new(reference, UserAgentBrowser::Firefox);
        let event = detector.detect(&baseline, &current);
        assert_eq!(event.new_divergences.len(), 3);
        let layers: BTreeSet<Layer> = event.bisect.changed_layers.iter().copied().collect();
        assert!(layers.contains(&Layer::Js));
        assert!(layers.contains(&Layer::Transport));
        assert!(layers.contains(&Layer::Behavioral));
    }

    #[test]
    fn serialization_round_trips_event() {
        let baseline = snapshot("baseline", vec![], vec![], vec![]);
        let current = snapshot(
            "current",
            vec![("navigator.webdriver", Severity::High, "true")],
            vec![],
            vec![],
        );
        let event = detector().detect(&baseline, &current);
        let json = serde_json::to_string(&event).expect("serialize");
        let back: DriftEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.alerted, event.alerted);
        assert_eq!(back.new_divergences.len(), event.new_divergences.len());
        assert_eq!(back.bisect, event.bisect);
    }
}
