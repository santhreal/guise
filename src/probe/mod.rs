//! Runtime stealth-surface probe + drift detector.
//!
//! [`crate::browser::apply_stealth`] injects JS overrides (the source is
//! [`crate::fingerprint::profile_js`]). That injection is a STATIC contract - it
//! asserts the override is present in the source. It does NOT verify that the
//! override WORKS at runtime: another script may have re-defined the property;
//! the browser build may not expose it at all; or the patched value may drift
//! from "looks like real Firefox."
//!
//! `StealthProbe` answers "does the page actually pass the
//! fingerprint tests" by probing 100+ live surfaces and comparing
//! against expected real-browser values. The output is a structured
//! drift report - for each probed surface, the report carries
//! `(expected, actual, severity)`. Operators run this in dev to
//! verify a stealth-profile change still passes; CI runs it
//! against a synthetic-page fixture to catch regressions where a
//! profile update accidentally drops a surface.
//!
//! No public captcha-solver crate ships a comparable runtime
//! drift detector. The closest prior art is the OSS
//! `creep-js` browser-side fingerprint disclosure tool - but
//! creep-js is a JS library a human runs in a browser, not a
//! Rust-side automated probe.
//!
//! The concrete data types ([`Probe`], [`ProbeOutcome`], [`Severity`],
//! [`Capture`], [`DifferentialReport`], …) live in the `guise-oracle`
//! contract crate so downstream consumers can share the taxonomy without
//! pulling in a browser driver. This module owns the runtime evaluation and
//! rendering logic.

use anyhow::{anyhow, Result};
use futures::future::join_all;
use runtime_foxdriver::Page;

pub use guise_oracle::{
    severity_rank, Capture, CapturedSurface, Determinism, DifferentialReport, Divergence,
    DivergenceKind, DriftReport, Probe, ProbeOutcome, ProbeReport, Severity, ThreeWayReport,
    ThreeWaySurface,
};

mod behavioral;
mod bidi_tells;
mod catalogue;
mod catalogue_extended;
mod catalogue_firefox;
mod catalogue_misc;
mod classify;
mod codec;
mod completeness;
mod creepjs;
mod drift;
mod fixture;
mod lie_detector;
mod oracle;
mod realm;
mod redteam;
pub mod scorecard;
pub mod surface_coverage;
#[cfg(test)]
mod tests;
#[cfg(feature = "http-headers")]
mod transport;

pub use behavioral::{
    behavioral_capture, compute_behavioral_fingerprint,
    enrich_capture as enrich_capture_behavioral, BehavioralFingerprint,
};
pub use catalogue::{probes, probes_for};
pub use completeness::{
    all_gaps, coverage_report, CheckCriticality, CoverageGap, CoverageReport, KnownCheck,
    KNOWN_FINGERPRINTER_CHECKS,
};
pub use drift::{BisectReport, DriftDetector, DriftEvent, DriftSnapshot, Layer, PersonaContext};
pub use fixture::synthetic_firefox_fixture;
pub use guise_profiles::UserAgentBrowser;
pub use oracle::{
    capture_page, diff_captures, diff_pages, full_stack_compare, render_differential,
    render_three_way, three_way_compare, FullStackReport,
};
pub use realm::worker_realm_is_self_coherent;
pub use scorecard::{scorecard_from_report, Scorecard, ScorecardEntry, ScorecardSurface};
pub use surface_coverage::{
    category_for_probe, divergence_kind_for_probe, persona_overridden_surface_ids,
    spoofed_surface_ids, surface_coverage, NoiseSpoofLink, ProbeSurfaceLink, SpoofSurfaceLink,
    SurfaceCoverage, NOISE_SPOOF_LINKS, PROBE_SURFACE_LINKS, SPOOF_SURFACE_LINKS,
};
#[cfg(feature = "http-headers")]
pub use transport::{
    compute_transport_fingerprint, enrich_capture as enrich_capture_transport, transport_capture,
    transport_suggests_linux_persona, TransportFingerprint,
};
/// Probe count target - used in tests to catch regressions where a
/// probe is silently dropped (G183).
pub const PROBE_COUNT_FLOOR: usize = 200;

/// Run every probe against the page; return a structured report.
///
/// Measures against Chrome truth (the back-compatible default). For a Firefox
/// disguise, what guise's live BiDi browser actually is, use [`run_for`] so
/// Chromium-only surfaces aren't falsely flagged.
///
/// Errors at the BiDi layer become `ProbeOutcome::ProbeError` rather
/// than failing the whole probe - operators see WHICH probe broke
/// rather than a single top-level error.
pub async fn run(page: &Page) -> Result<DriftReport> {
    run_for(page, UserAgentBrowser::Chrome).await
}

/// Run the family-aware probe catalogue for `browser` against the page.
///
/// See [`probes_for`]: a Firefox target drops the Chromium-only surfaces and
/// adds the Firefox truths, so the drift report reflects whether the disguise
/// is coherent with the *target* browser rather than always with Chrome.
///
/// G219: probes are evaluated concurrently over BiDi so oracle runtime scales
/// with the slowest probe rather than the sum of all probe latencies. The
/// resulting report still preserves catalogue order, so offline diffs and
/// renderings remain deterministic.
pub async fn run_for(page: &Page, browser: UserAgentBrowser) -> Result<DriftReport> {
    let catalogue = probes_for(browser);
    let mut work = Vec::with_capacity(catalogue.len());
    for probe in catalogue {
        // Copy the small probe metadata into the async block so the futures are
        // independent and can run concurrently without borrowing the catalogue.
        let js = probe.js;
        let name = probe.name.to_string();
        let severity = probe.severity;
        let classifier = probe.classifier;
        work.push(async move {
            // `evaluate_await` (BiDi awaitPromise) so async probes, the codec
            // matrix (MediaCapabilities.decodingInfo) and the Worker/ServiceWorker
            // realm round-trips, resolve to their real value. With the plain
            // `evaluate`, a Promise-returning probe handed back an opaque handle:
            // the codec probe ProbeError'd ("no ua") and the realm probes saw
            // `null`: which a "tell-absent → Pass" classifier scored as a SILENT
            // false pass (Law 10). A non-promise probe is returned unchanged, so
            // this is safe for the deterministic majority.
            let outcome = match page.evaluate_await(js).await {
                // Law 10 / G261: a result that fails to deserialize is a PROBE ERROR, not
                // a value to classify. The prior `.unwrap_or(Value::Null)` ran the
                // classifier on `null`, which a "tell-absent → Pass" classifier scores as
                // a clean PASS, a failed read silently counted as a stealth win and never
                // reached `report.probe_errors`. Route it through the same ProbeError arm
                // an evaluate failure already uses.
                Ok(eval) => match eval.into_value::<serde_json::Value>() {
                    Ok(value) => classifier(&value),
                    Err(e) => ProbeOutcome::ProbeError(format!(
                        "probe result did not deserialize as JSON: {e}"
                    )),
                },
                Err(e) => ProbeOutcome::ProbeError(e.to_string()),
            };
            ProbeReport {
                name,
                severity: format!("{:?}", severity),
                outcome,
            }
        });
    }

    let reports = join_all(work).await;
    let probed = reports.len();
    let mut passed = 0usize;
    let mut drift = 0usize;
    let mut critical = 0usize;
    let mut probe_errors = 0usize;
    for r in &reports {
        match &r.outcome {
            ProbeOutcome::Pass => passed += 1,
            ProbeOutcome::Drift(_) => drift += 1,
            ProbeOutcome::Critical(_) => critical += 1,
            ProbeOutcome::ProbeError(_) => probe_errors += 1,
        }
    }

    Ok(DriftReport {
        probed,
        passed,
        drift,
        critical,
        probe_errors,
        per_probe: reports,
    })
}

/// Diagnostic helper: render the report as a human-readable table.
pub fn render_report(report: &DriftReport) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(report.per_probe.len() * 120);
    let _ = writeln!(out, "STEALTH PROBE - {}", report.summary());
    let _ = writeln!(out, "{:-^100}", "");
    for r in &report.per_probe {
        let icon = match &r.outcome {
            ProbeOutcome::Pass => "✓",
            ProbeOutcome::Drift(_) => "~",
            ProbeOutcome::Critical(_) => "✘",
            ProbeOutcome::ProbeError(_) => "?",
        };
        let detail = match &r.outcome {
            ProbeOutcome::Pass => String::new(),
            ProbeOutcome::Drift(m) | ProbeOutcome::Critical(m) | ProbeOutcome::ProbeError(m) => {
                format!(" - {m}")
            }
        };
        let _ = writeln!(out, "  {icon} [{}] {}{}", r.severity, r.name, detail);
    }
    out
}

/// Apply every probe and return Result. Sugar over [`run`] for the
/// CLI subcommand wrapper. Uses the Chromium catalogue; for a Firefox disguise
/// use [`audit_page_for`].
pub async fn audit_page(page: &Page) -> Result<DriftReport> {
    audit_page_for(page, UserAgentBrowser::Chrome).await
}

/// Family-aware variant of [`audit_page`]: probe against `browser`'s real
/// fingerprint. Sugar over [`run_for`].
pub async fn audit_page_for(page: &Page, browser: UserAgentBrowser) -> Result<DriftReport> {
    let r = run_for(page, browser)
        .await
        .map_err(|e| anyhow!("probe run failed: {e}"))?;
    Ok(r)
}

#[cfg(test)]
mod into_value_no_swallow_audit {
    //! G261 / Law 10 (read-back deserialization must SURFACE, never swallow).
    //! Three separate sites (`fingerprint/evasion.rs`, `probe/oracle.rs`, and the
    //! probe runner above) independently grew the SAME bug: an `into_value` read
    //! paired with a result-swallow, which turns a result that failed to
    //! deserialize into a clean read of `null`. A "tell-absent → Pass" classifier
    //! then scores that failed read as a stealth PASS, and the differential oracle
    //! scores two such reads as "fingerprint-identical", false verdicts
    //! manufactured from failed probes. This guard walks the crate source and
    //! fails if any `into_value` read-back is paired with a swallowing token, so
    //! the pattern cannot regress a fourth time.
    //!
    //! Self-immunity: tokens are assembled with `concat!` so the joined literals
    //! never appear in this file; pure-comment lines are skipped (the prose above
    //! names the banned constructs on purpose).
    use std::fs;
    use std::path::{Path, PathBuf};

    fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }

    fn is_full_line_comment(line: &str) -> bool {
        line.trim_start().starts_with("//")
    }

    #[test]
    fn into_value_reads_never_swallow_a_deserialize_failure() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rs_files(&root.join("src"), &mut files);

        let read_token = concat!("into_", "value");
        let swallow_tokens = [concat!("unwrap", "_or"), concat!(".ok", "()")];

        let mut scanned = 0usize;
        for f in &files {
            let Ok(src) = fs::read_to_string(f) else {
                continue;
            };
            for (idx, line) in src.lines().enumerate() {
                if is_full_line_comment(line) || !line.contains(read_token) {
                    continue;
                }
                scanned += 1;
                if let Some(swallow) = swallow_tokens.iter().find(|t| line.contains(*t)) {
                    panic!(
                        "{}:{}: an `into_value` read-back is paired with the result-swallowing \
                         token {swallow:?} (Law 10 / G261). A swallowed deserialize coerces a failed \
                         probe read into a clean value, which classifiers and the differential oracle \
                         score as a false PASS / false agreement. Surface it (match / map_err(...)? \
                         to an error cell or ProbeError), never a swallow. Line: {}",
                        f.display(),
                        idx + 1,
                        line.trim()
                    );
                }
            }
        }
        // The three known read-back sites must still be seen; a lower count means
        // the token drifted from the real source and the guard has gone inert.
        assert!(
            scanned >= 3,
            "into_value audit matched only {scanned} read-back sites, the token drifted from \
             the real source and the guard is now inert"
        );
    }
}
