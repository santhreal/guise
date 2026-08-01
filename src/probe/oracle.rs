//! Differential fingerprint oracle, diff two browsers across the surface
//! catalogue.
//!
//! [`run_for`](super::run_for) probes ONE page against expected real-browser
//! truth. The oracle instead runs the *same* family catalogue against TWO live
//! pages and compares the **raw returned values** surface-by-surface. Any
//! surface where they disagree is a [`Divergence`] carrying the surface name,
//! the catalogue [`Severity`], and both rendered values.
//!
//! This is the validation gate for the `reynard` engine fork: a patched
//! browser is "zero engine-level fingerprint" exactly when it is
//! byte-identical to a stock build across the whole catalogue
//! `report.is_identical()`. Run against the JS disguise instead and the
//! divergences ARE its residual tells (e.g. an overridden UA version or
//! `hardwareConcurrency` that no longer matches the real binary).
//!
//! The taxonomy is guise's own [`probes_for`](super::probes_for) catalogue (no
//! duplication); the [`Divergence`]/severity shape mirrors sear's
//! `differential::Divergence` so a detector (sear) and an evader (reynard) can
//! later share one surface taxonomy: sear detects against it, reynard evades
//! across it, this oracle gates on it.

use super::probes_for;
use super::surface_coverage::divergence_kind_for_probe;
use anyhow::Result;
use futures::future::join_all;
use guise_oracle::{
    severity_rank, Capture, CapturedSurface, Determinism, DifferentialReport, Divergence,
    ThreeWayReport, ThreeWaySurface,
};
use guise_profiles::UserAgentBrowser;
use runtime_foxdriver::Page;
use serde::{Deserialize, Serialize};

/// Render every surface value of `page` from the `browser` family catalogue.
/// `Ok(json)` for a clean read, `Err(msg)` if the probe failed to evaluate.
///
/// G219: probes are evaluated concurrently over BiDi so oracle runtime scales
/// with the slowest probe rather than the sum of all probe latencies. The
/// resulting `Capture` still preserves catalogue order, so offline diffs remain
/// deterministic.
pub async fn capture_page(page: &Page, browser: UserAgentBrowser, label: &str) -> Result<Capture> {
    let catalogue = probes_for(browser);
    let mut work = Vec::with_capacity(catalogue.len());
    for probe in catalogue {
        // Copy the small probe metadata into the async block so the futures are
        // independent and can run concurrently without borrowing the catalogue.
        let js = probe.js;
        let name = probe.name;
        let severity = probe.severity;
        let determinism = probe.determinism;
        let classifier = probe.classifier;
        work.push(async move {
            // awaitPromise so async probes (codec matrix, Worker/ServiceWorker
            // realm round-trips) resolve to their real value instead of an opaque
            // promise handle that deserializes to `null`. See run_for.
            let cell = match page.evaluate_await(js).await {
                // Law 10 / G261: surface a deserialize failure as a probe ERROR, never
                // coerce to `Null`. The prior `.unwrap_or(Value::Null)` turned a result
                // that failed to deserialize into a clean read of `null`; if BOTH browser
                // families hit that path the oracle would compare "null" == "null" and
                // report fingerprint-IDENTICAL, a FALSE PASS manufactured from two failed
                // reads. An error cell is treated as a probe failure (not a divergence,
                // not agreement), exactly as an evaluate failure already is below.
                Ok(eval) => match eval.into_value::<serde_json::Value>() {
                    Ok(v) => match determinism {
                        // Reproducible surfaces diff by raw value.
                        Determinism::Deterministic => Ok(v.to_string()),
                        // Noisy surfaces (timer entropy, scheduler jitter) diff by the
                        // classified outcome class, so two healthy-but-numerically-different
                        // reads agree instead of flagging a false divergence.
                        Determinism::Stochastic => Ok(classifier(&v).class_label().to_string()),
                    },
                    Err(e) => Err(format!("probe result did not deserialize as JSON: {e}")),
                },
                Err(e) => Err(e.to_string()),
            };
            CapturedSurface {
                name: name.to_string(),
                severity,
                value: cell,
            }
        });
    }
    let surfaces = join_all(work).await;
    Ok(Capture {
        label: label.to_string(),
        surfaces,
    })
}

/// Diff two offline captures surface-by-surface.
///
/// This is the deterministic, no-browser core of the oracle (G190). Live tests
/// use [`diff_pages`]; CI fixtures use this function directly.
pub fn diff_captures(a: &Capture, b: &Capture) -> DifferentialReport {
    let b_by_name = b.by_name();

    let mut report = DifferentialReport {
        label_a: a.label.clone(),
        label_b: b.label.clone(),
        surfaces: 0,
        agreed: 0,
        diverged: 0,
        errors: 0,
        divergences: Vec::new(),
    };

    for surface in &a.surfaces {
        let Some((sev_b, vb)) = b_by_name.get(surface.name.as_str()) else {
            // Surface only present in A's capture, treat as an error rather
            // than a silent drop so coverage gaps are visible.
            report.errors += 1;
            report.surfaces += 1;
            continue;
        };
        report.surfaces += 1;
        match (&surface.value, vb) {
            (Ok(x), Ok(y)) if x == y => report.agreed += 1,
            (Ok(x), Ok(y)) => {
                report.diverged += 1;
                report.divergences.push(Divergence {
                    surface: surface.name.clone(),
                    surface_id: super::surface_coverage::surface_id_for_probe(&surface.name)
                        .map(|s| s.to_string()),
                    severity: surface.severity,
                    kind: divergence_kind_for_probe(&surface.name),
                    a_value: x.clone(),
                    b_value: y.clone(),
                });
            }
            _ => report.errors += 1,
        }
        // Sanity: severity should match between captures. If it doesn't, the
        // catalogue changed between captures, surface it as an error rather
        // than silently use A's severity.
        if surface.severity != **sev_b {
            report.errors += 1;
        }
    }

    // Surfaces unique to B's capture (shouldn't happen for one family, but
    // keep the accounting honest).
    let a_names: std::collections::HashSet<&str> =
        a.surfaces.iter().map(|s| s.name.as_str()).collect();
    for surface in &b.surfaces {
        if !a_names.contains(surface.name.as_str()) {
            report.errors += 1;
            report.surfaces += 1;
        }
    }

    report.divergences.sort_by(|x, y| {
        severity_rank(&y.severity)
            .cmp(&severity_rank(&x.severity))
            .then(x.surface.cmp(&y.surface))
    });

    report
}

/// Run the `browser` family catalogue against both pages and diff the raw
/// values surface-by-surface.
///
/// Surfaces are matched by name (robust to any catalogue reordering). A surface
/// counts as an error, not a divergence, if either browser fails to evaluate
/// it, so a transport hiccup never masquerades as a fingerprint tell.
pub async fn diff_pages(
    a: &Page,
    b: &Page,
    browser: UserAgentBrowser,
    label_a: &str,
    label_b: &str,
) -> Result<DifferentialReport> {
    let cap_a = capture_page(a, browser, label_a).await?;
    let cap_b = capture_page(b, browser, label_b).await?;
    Ok(diff_captures(&cap_a, &cap_b))
}

/// Compare stock Firefox, patched reynard, and the JS disguise captures
/// surface-by-surface (G182).
///
/// Only surfaces present with clean values in all three captures are compared;
/// probe errors are skipped rather than treated as a divergence.
pub fn three_way_compare(stock: &Capture, reynard: &Capture, disguise: &Capture) -> ThreeWayReport {
    let r_by_name = reynard.by_name();
    let d_by_name = disguise.by_name();

    let mut report = ThreeWayReport {
        surfaces: 0,
        engine_wins: Vec::new(),
        js_wins: Vec::new(),
        everyone_loses: Vec::new(),
    };

    for surface in &stock.surfaces {
        let Some((_, rv)) = r_by_name.get(surface.name.as_str()) else {
            continue;
        };
        let Some((_, dv)) = d_by_name.get(surface.name.as_str()) else {
            continue;
        };
        let (Ok(sv), Ok(rv), Ok(dv)) = (&surface.value, rv, dv) else {
            continue;
        };
        report.surfaces += 1;
        if sv == rv && sv != dv {
            report.engine_wins.push(ThreeWaySurface {
                surface: surface.name.clone(),
                surface_id: super::surface_coverage::surface_id_for_probe(&surface.name)
                    .map(|s| s.to_string()),
                severity: surface.severity,
                stock_value: sv.clone(),
                reynard_value: rv.clone(),
                disguise_value: dv.clone(),
            });
        } else if sv == dv && sv != rv {
            report.js_wins.push(ThreeWaySurface {
                surface: surface.name.clone(),
                surface_id: super::surface_coverage::surface_id_for_probe(&surface.name)
                    .map(|s| s.to_string()),
                severity: surface.severity,
                stock_value: sv.clone(),
                reynard_value: rv.clone(),
                disguise_value: dv.clone(),
            });
        } else if sv != rv && sv != dv && rv != dv {
            report.everyone_loses.push(ThreeWaySurface {
                surface: surface.name.clone(),
                surface_id: super::surface_coverage::surface_id_for_probe(&surface.name)
                    .map(|s| s.to_string()),
                severity: surface.severity,
                stock_value: sv.clone(),
                reynard_value: rv.clone(),
                disguise_value: dv.clone(),
            });
        }
    }

    let sort = |v: &mut Vec<ThreeWaySurface>| {
        v.sort_by(|x, y| {
            severity_rank(&y.severity)
                .cmp(&severity_rank(&x.severity))
                .then(x.surface.cmp(&y.surface))
        });
    };
    sort(&mut report.engine_wins);
    sort(&mut report.js_wins);
    sort(&mut report.everyone_loses);

    report
}

/// Result of comparing two personas across all three layers: JavaScript
/// surfaces, transport fingerprints, and behavioral realism (G205). This is the
/// report type the full-stack oracle emits; it keeps each layer separate so an
/// operator can see whether a regression is in the browser patch, the TLS/H2
/// shape, or the human-behavior model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullStackReport {
    /// Baseline label (e.g. `"stock-firefox"`).
    pub label_a: String,
    /// Candidate label (e.g. `"reynard"` or `"guise-persona"`).
    pub label_b: String,
    /// JavaScript-surface differential report.
    pub js: DifferentialReport,
    /// Transport-layer (JA3/JA4/H2/TCP) differential report.
    pub transport: DifferentialReport,
    /// Behavioral-layer (timing/typing/mouse) differential report.
    pub behavioral: DifferentialReport,
}

impl FullStackReport {
    /// `true` when all three layers are fingerprint-identical.
    pub fn is_identical(&self) -> bool {
        self.js.is_identical() && self.transport.is_identical() && self.behavioral.is_identical()
    }

    /// All divergences across the three layers, sorted by severity then name.
    pub fn combined_divergences(&self) -> Vec<Divergence> {
        let mut all = Vec::with_capacity(
            self.js.divergences.len()
                + self.transport.divergences.len()
                + self.behavioral.divergences.len(),
        );
        all.extend(self.js.divergences.iter().cloned());
        all.extend(self.transport.divergences.iter().cloned());
        all.extend(self.behavioral.divergences.iter().cloned());
        all.sort_by(|x, y| {
            severity_rank(&y.severity)
                .cmp(&severity_rank(&x.severity))
                .then(x.surface.cmp(&y.surface))
        });
        all
    }

    /// Merge the three layer reports into one [`super::scorecard::Scorecard`] so
    /// a single CI regression gate can score the full persona (G206).
    pub fn combined_scorecard(
        &self,
        browser: crate::fingerprint::UserAgentBrowser,
    ) -> super::scorecard::Scorecard {
        let combined = DifferentialReport {
            label_a: self.label_a.clone(),
            label_b: self.label_b.clone(),
            surfaces: self.js.surfaces + self.transport.surfaces + self.behavioral.surfaces,
            agreed: self.js.agreed + self.transport.agreed + self.behavioral.agreed,
            diverged: self.js.diverged + self.transport.diverged + self.behavioral.diverged,
            errors: self.js.errors + self.transport.errors + self.behavioral.errors,
            divergences: self.combined_divergences(),
        };
        super::scorecard::scorecard_from_report(&combined, browser)
    }

    /// One-line human summary per layer.
    pub fn summary(&self) -> String {
        format!(
            "full-stack: JS [{}] | transport [{}] | behavioral [{}]",
            self.js.summary(),
            self.transport.summary(),
            self.behavioral.summary()
        )
    }
}

/// Diff two personas across the JS, transport, and behavioral layers.
pub fn full_stack_compare(
    js_a: &Capture,
    transport_a: &Capture,
    behavioral_a: &Capture,
    js_b: &Capture,
    transport_b: &Capture,
    behavioral_b: &Capture,
) -> FullStackReport {
    FullStackReport {
        label_a: js_a.label.clone(),
        label_b: js_b.label.clone(),
        js: diff_captures(js_a, js_b),
        transport: diff_captures(transport_a, transport_b),
        behavioral: diff_captures(behavioral_a, behavioral_b),
    }
}

/// Render a three-way report as a human-readable table.
pub fn render_three_way(report: &ThreeWayReport) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(1024);
    let _ = writeln!(out, "THREE-WAY ORACLE: {}", report.summary());
    let _ = writeln!(out, "{:-^100}", "");
    if report.engine_wins.is_empty()
        && report.js_wins.is_empty()
        && report.everyone_loses.is_empty()
    {
        let _ = writeln!(
            out,
            "  ✓ stock, reynard, and disguise agree on every compared surface"
        );
        return out;
    }
    for s in &report.engine_wins {
        let _ = writeln!(
            out,
            "  ✓ [ENGINE WIN] [{:?}] {}\n      stock    = {}\n      reynard  = {}\n      disguise = {}",
            s.severity, s.surface, s.stock_value, s.reynard_value, s.disguise_value
        );
    }
    for s in &report.js_wins {
        let _ = writeln!(
            out,
            "  ~ [JS WIN] [{:?}] {}\n      stock    = {}\n      reynard  = {}\n      disguise = {}",
            s.severity, s.surface, s.stock_value, s.reynard_value, s.disguise_value
        );
    }
    for s in &report.everyone_loses {
        let _ = writeln!(
            out,
            "  ✘ [EVERYONE LOSES] [{:?}] {}\n      stock    = {}\n      reynard  = {}\n      disguise = {}",
            s.severity, s.surface, s.stock_value, s.reynard_value, s.disguise_value
        );
    }
    out
}

/// Render the differential report as a human-readable table (High severity
/// first (the surfaces a fingerprinter weights most)).
pub fn render_differential(report: &DifferentialReport) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(report.divergences.len() * 120 + 128);
    let _ = writeln!(out, "DIFFERENTIAL ORACLE: {}", report.summary());
    let _ = writeln!(out, "{:-^100}", "");
    if report.divergences.is_empty() {
        let _ = writeln!(
            out,
            "  ✓ fingerprint-identical across {} surfaces",
            report.surfaces
        );
        return out;
    }
    // Defensive sort so rendering is deterministic regardless of how the report
    // was constructed (G218).
    let mut divs: Vec<_> = report.divergences.iter().collect();
    divs.sort_by(|x, y| {
        severity_rank(&y.severity)
            .cmp(&severity_rank(&x.severity))
            .then(x.surface.cmp(&y.surface))
    });
    for d in divs {
        // Tag the divergence with its inventory surface family (the shared G119
        // taxonomy) when the probe is bridged, so an operator can group tells by
        // category (Navigator / WebGl / Canvas / …) instead of reading bare names.
        let category = match super::category_for_probe(&d.surface) {
            Some(cat) => format!(" {{{cat:?}}}"),
            None => String::new(),
        };
        let _ = writeln!(
            out,
            "  ✘ [{:?}]{} {} ({:?})\n      {} = {}\n      {} = {}",
            d.severity,
            category,
            d.surface,
            d.kind,
            report.label_a,
            d.a_value,
            report.label_b,
            d.b_value
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{Divergence, Severity};

    fn rep(divs: Vec<Divergence>, errors: usize) -> DifferentialReport {
        DifferentialReport {
            label_a: "a".into(),
            label_b: "b".into(),
            surfaces: 10,
            agreed: 10 - divs.len() - errors,
            diverged: divs.len(),
            errors,
            divergences: divs,
        }
    }

    fn div(surface: &str, sev: Severity) -> Divergence {
        Divergence {
            surface: surface.into(),
            surface_id: crate::probe::surface_coverage::surface_id_for_probe(surface)
                .map(|s| s.to_string()),
            severity: sev,
            kind: divergence_kind_for_probe(surface),
            a_value: "1".into(),
            b_value: "2".into(),
        }
    }

    #[test]
    fn identical_requires_zero_diverged_and_zero_errors() {
        assert!(rep(vec![], 0).is_identical());
        assert!(!rep(vec![div("x", Severity::Low)], 0).is_identical());
        assert!(!rep(vec![], 1).is_identical());
    }

    #[test]
    fn worst_picks_highest_severity() {
        let r = rep(
            vec![
                div("a", Severity::Low),
                div("b", Severity::High),
                div("c", Severity::Medium),
            ],
            0,
        );
        assert_eq!(r.worst(), Some(Severity::High));
    }

    #[test]
    fn worst_is_none_when_identical() {
        assert_eq!(rep(vec![], 0).worst(), None);
    }

    #[test]
    fn render_reports_identical_when_no_divergences() {
        let out = render_differential(&rep(vec![], 0));
        assert!(out.contains("fingerprint-identical"));
    }

    #[test]
    fn render_lists_each_divergence_with_both_values() {
        let out = render_differential(&rep(vec![div("webgl.renderer", Severity::High)], 0));
        assert!(out.contains("webgl.renderer"));
        assert!(out.contains("a = 1"));
        assert!(out.contains("b = 2"));
    }

    #[test]
    fn summary_names_both_browsers() {
        let s = rep(vec![], 0).summary();
        assert!(s.contains("a vs b"));
        assert!(s.contains("10/10"));
    }

    #[test]
    fn engine_divergence_count_excludes_persona_intended() {
        // hardwareConcurrency is persona-overridden → PersonaIntended (expected
        // persona-vs-host); webdriver is not → EngineDivergence (investigate).
        let r = rep(
            vec![
                div("navigator.hardwareConcurrency in [2, 16]", Severity::Low),
                div("navigator.webdriver", Severity::High),
            ],
            0,
        );
        assert_eq!(r.engine_divergence_count(), 1);
        let engine: Vec<_> = r.engine_divergences().map(|d| d.surface.as_str()).collect();
        assert_eq!(engine, vec!["navigator.webdriver"]);
    }

    #[test]
    fn render_tags_a_bridged_divergence_with_its_surface_category() {
        // A real bridged probe name resolves to its inventory category (G119),
        // so the human report groups tells by surface family.
        let out = render_differential(&rep(vec![div("navigator.webdriver", Severity::High)], 0));
        assert!(
            out.contains("{Navigator}"),
            "expected category tag in:\n{out}"
        );
        assert!(out.contains("navigator.webdriver"));
        // An unbridged probe name renders with no category tag (no fabrication).
        let out2 = render_differential(&rep(
            vec![div("window.__nightmare undefined", Severity::Medium)],
            0,
        ));
        assert!(
            !out2.contains('{'),
            "unbridged probe must not get a category: {out2}"
        );
    }

    #[test]
    fn render_is_deterministic_for_same_divergences_in_any_order() {
        // G218: the oracle output must be byte-identical across runs so CI diffs
        // and scorecards are stable. The capture logic sorts by severity then name.
        let divs_a = vec![
            div("zzz", Severity::Low),
            div("aaa", Severity::High),
            div("mmm", Severity::Medium),
        ];
        let mut divs_b = divs_a.clone();
        divs_b.reverse();
        let out_a = render_differential(&rep(divs_a, 0));
        let out_b = render_differential(&rep(divs_b, 0));
        assert_eq!(
            out_a, out_b,
            "same divergence set must render identically regardless of input order"
        );
    }

    fn cap(label: &str, surfaces: Vec<(&str, Severity, &str)>) -> Capture {
        Capture {
            label: label.to_string(),
            surfaces: surfaces
                .into_iter()
                .map(|(n, s, v)| CapturedSurface {
                    name: n.to_string(),
                    severity: s,
                    value: Ok(v.to_string()),
                })
                .collect(),
        }
    }

    fn cap_err(
        label: &str,
        surfaces: Vec<(&str, Severity, std::result::Result<&str, &str>)>,
    ) -> Capture {
        Capture {
            label: label.to_string(),
            surfaces: surfaces
                .into_iter()
                .map(|(n, s, v)| CapturedSurface {
                    name: n.to_string(),
                    severity: s,
                    value: v.map(|s| s.to_string()).map_err(|s| s.to_string()),
                })
                .collect(),
        }
    }

    #[test]
    fn three_way_detects_engine_win() {
        let stock = cap("stock", vec![("x", Severity::High, "1")]);
        let reynard = cap("reynard", vec![("x", Severity::High, "1")]);
        let disguise = cap("disguise", vec![("x", Severity::High, "2")]);
        let report = three_way_compare(&stock, &reynard, &disguise);
        assert_eq!(report.engine_wins.len(), 1);
        assert_eq!(report.js_wins.len(), 0);
        assert_eq!(report.everyone_loses.len(), 0);
        assert!(report.engine_better_than_js());
    }

    #[test]
    fn three_way_detects_js_win() {
        let stock = cap("stock", vec![("x", Severity::High, "1")]);
        let reynard = cap("reynard", vec![("x", Severity::High, "2")]);
        let disguise = cap("disguise", vec![("x", Severity::High, "1")]);
        let report = three_way_compare(&stock, &reynard, &disguise);
        assert_eq!(report.engine_wins.len(), 0);
        assert_eq!(report.js_wins.len(), 1);
        assert_eq!(report.everyone_loses.len(), 0);
        assert!(!report.engine_better_than_js());
    }

    #[test]
    fn three_way_detects_everyone_loses() {
        let stock = cap("stock", vec![("x", Severity::High, "1")]);
        let reynard = cap("reynard", vec![("x", Severity::High, "2")]);
        let disguise = cap("disguise", vec![("x", Severity::High, "3")]);
        let report = three_way_compare(&stock, &reynard, &disguise);
        assert_eq!(report.engine_wins.len(), 0);
        assert_eq!(report.js_wins.len(), 0);
        assert_eq!(report.everyone_loses.len(), 1);
    }

    #[test]
    fn three_way_ignores_agreement_and_errors() {
        let stock = cap_err(
            "stock",
            vec![
                ("agree", Severity::Low, Ok("1")),
                ("err", Severity::Low, Ok("1")),
                ("only-stock", Severity::Low, Ok("1")),
            ],
        );
        let reynard = cap_err(
            "reynard",
            vec![
                ("agree", Severity::Low, Ok("1")),
                ("err", Severity::Low, Ok("1")),
            ],
        );
        let disguise = cap_err(
            "disguise",
            vec![
                ("agree", Severity::Low, Ok("1")),
                ("err", Severity::Low, Err("probe error")),
            ],
        );
        let report = three_way_compare(&stock, &reynard, &disguise);
        assert_eq!(report.surfaces, 1);
        assert_eq!(report.engine_wins.len(), 0);
        assert_eq!(report.js_wins.len(), 0);
        assert_eq!(report.everyone_loses.len(), 0);
    }

    #[test]
    fn three_way_render_is_deterministic() {
        let stock = cap("stock", vec![("x", Severity::High, "1")]);
        let reynard = cap("reynard", vec![("x", Severity::High, "1")]);
        let disguise = cap("disguise", vec![("x", Severity::High, "2")]);
        let r1 = render_three_way(&three_way_compare(&stock, &reynard, &disguise));
        let r2 = render_three_way(&three_way_compare(&stock, &reynard, &disguise));
        assert_eq!(r1, r2);
    }

    // ─── Full-stack oracle (G205) ───────────────────────────────────────────

    #[test]
    fn full_stack_is_identical_when_all_layers_match() {
        let js = cap("a", vec![("x", Severity::High, "1")]);
        let transport = cap("a", vec![("transport.ja4", Severity::High, "abc")]);
        let behavioral = cap(
            "a",
            vec![("behavioral.realism_score", Severity::High, "95")],
        );
        let report = full_stack_compare(&js, &transport, &behavioral, &js, &transport, &behavioral);
        assert!(report.is_identical());
        assert!(report
            .combined_scorecard(crate::fingerprint::UserAgentBrowser::Firefox)
            .is_clean());
    }

    #[test]
    fn full_stack_reports_divergences_in_each_layer() {
        let js_a = cap("a", vec![("x", Severity::High, "1")]);
        let js_b = cap("b", vec![("x", Severity::High, "2")]);
        let transport_a = cap("a", vec![("transport.ja4", Severity::High, "abc")]);
        let transport_b = cap("b", vec![("transport.ja4", Severity::High, "def")]);
        let behavioral_a = cap(
            "a",
            vec![("behavioral.realism_score", Severity::High, "95")],
        );
        let behavioral_b = cap(
            "b",
            vec![("behavioral.realism_score", Severity::High, "60")],
        );

        let report = full_stack_compare(
            &js_a,
            &transport_a,
            &behavioral_a,
            &js_b,
            &transport_b,
            &behavioral_b,
        );
        assert!(!report.is_identical());
        assert_eq!(report.js.diverged, 1);
        assert_eq!(report.transport.diverged, 1);
        assert_eq!(report.behavioral.diverged, 1);

        let combined = report.combined_divergences();
        let div_names: std::collections::HashSet<&str> =
            combined.iter().map(|d| d.surface.as_str()).collect();
        assert!(div_names.contains("x"));
        assert!(div_names.contains("transport.ja4"));
        assert!(div_names.contains("behavioral.realism_score"));
    }

    #[test]
    fn full_stack_combined_scorecard_sums_lost_points() {
        let js_a = cap("a", vec![("navigator.webdriver", Severity::High, "false")]);
        let js_b = cap("b", vec![("navigator.webdriver", Severity::High, "true")]);
        let transport_a = cap("a", vec![("transport.ja4", Severity::High, "abc")]);
        let transport_b = cap("b", vec![("transport.ja4", Severity::High, "def")]);
        let behavioral_a = cap(
            "a",
            vec![("behavioral.realism_score", Severity::High, "95")],
        );
        let behavioral_b = cap(
            "b",
            vec![("behavioral.realism_score", Severity::High, "60")],
        );

        let report = full_stack_compare(
            &js_a,
            &transport_a,
            &behavioral_a,
            &js_b,
            &transport_b,
            &behavioral_b,
        );
        let sc = report.combined_scorecard(crate::fingerprint::UserAgentBrowser::Firefox);
        assert!(
            sc.lost_points > 100,
            "combined scorecard must accumulate points from all layers"
        );
        assert_eq!(sc.diverged, 3);
        assert_eq!(sc.surfaces, 3);
    }
}
