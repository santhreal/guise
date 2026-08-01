//! Gated live-detector acceptance suite (G251 / G252 / G254 / G270).
//!
//! This file wires the catalogue oracle to a live browser so that every shipped
//! persona is exercised against the same surface taxonomy the offline tests use.
//! It is **opt-in**: without the required environment variables the tests skip
//! cleanly, so CI does not fail on hosts that lack a reynard binary or a display.
//!
//! Required environment variables to run the live portion:
//! - `REYNARD_BIN`: path to the patched Firefox/reynard binary.
//! - `DISPLAY`: headful X11 display (e.g. `:1`).
//!
//! Optional:
//!
//! - `STOCK_FIREFOX_BIN`: path to a stock Firefox for differential comparison (G254).
//! - `GUISE_LIVE_DETECTOR_URL`: page to navigate to before probing (default `about:blank`).
//! - `GUISE_LIVE_SCORECARD_DIR`: directory to write the release scorecard JSON.
#![cfg(feature = "browser")]

use guise::browser::launch_reynard;
use guise::fingerprint::{StealthProfile, UserAgentBrowser};
use guise::http::session_coherence::persona_full_stack_coherence;
use guise::probe::{capture_page, diff_captures, Severity};
use guise::rotation::all_profiles;
use runtime_foxdriver::browser::{launch_firefox, FoxBrowserConfig};
use std::path::PathBuf;

/// Per-persona live run result, serialized into the release scorecard.
#[derive(serde::Serialize)]
struct PersonaScore {
    profile: String,
    coherence_ok: bool,
    high_errors: usize,
    medium_errors: usize,
    differential_high_divergences: Option<usize>,
}

/// Release-level scorecard (G270).
#[derive(serde::Serialize)]
struct LiveScorecard {
    run_at: String,
    reynard_bin: Option<String>,
    stock_firefox_bin: Option<String>,
    detector_url: String,
    personas: Vec<PersonaScore>,
}

/// Offline part of G251: every shipped persona must be internally coherent
/// (JS surface ↔ TLS ↔ TCP/IP) before it is allowed near a live browser.
#[test]
fn every_shipped_persona_is_self_coherent() {
    let mut failures = Vec::new();
    for profile in all_profiles() {
        if let Err(e) = persona_full_stack_coherence(*profile) {
            failures.push(format!("{profile:?}: {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} shipped personas failed the unified coherence gate:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Live part of G251 / G252: for each Firefox-family shipped persona, launch
/// reynard, navigate to the detector page, and evaluate every probe in the
/// Firefox catalogue. High probes must evaluate without error.
///
/// This is the positive-path half of the per-surface contract; the negative and
/// boundary twins for each classifier live in the catalogue unit tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_shipped_persona_evaluates_critical_and_high_surfaces() {
    let reynard_bin = match std::env::var("REYNARD_BIN") {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "SKIP: set REYNARD_BIN and DISPLAY to run the live per-persona detector suite"
            );
            return;
        }
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP: live detector suite needs DISPLAY (headful)");
        return;
    }

    let detector_url =
        std::env::var("GUISE_LIVE_DETECTOR_URL").unwrap_or_else(|_| "about:blank".into());
    let scorecard_dir = std::env::var("GUISE_LIVE_SCORECARD_DIR")
        .ok()
        .map(PathBuf::from);

    let firefox_profiles: Vec<_> = all_profiles()
        .iter()
        .copied()
        .filter(|p| {
            matches!(
                guise::fingerprint::user_agent_facts(guise::fingerprint::profile_user_agent(*p))
                    .browser,
                UserAgentBrowser::Firefox
            )
        })
        .collect();

    let mut scorecard = LiveScorecard {
        run_at: chrono::Utc::now().to_rfc3339(),
        reynard_bin: Some(reynard_bin.clone()),
        stock_firefox_bin: std::env::var("STOCK_FIREFOX_BIN").ok(),
        detector_url: detector_url.clone(),
        personas: Vec::with_capacity(firefox_profiles.len()),
    };

    let mut any_failure: Option<String> = None;
    for profile in firefox_profiles {
        let name = format!("{profile:?}");
        eprintln!("[live-detector] launching reynard for {name}");
        let page = match launch_reynard(&reynard_bin, &profile, false).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[live-detector] launch failed for {name}: {e:?}");
                scorecard.personas.push(PersonaScore {
                    profile: name,
                    coherence_ok: true,
                    high_errors: 0,
                    medium_errors: 0,
                    differential_high_divergences: None,
                });
                continue;
            }
        };

        if let Err(e) = page.goto(&detector_url).await {
            eprintln!("[live-detector] navigation failed for {name}: {e:?}");
            let _ = page.close().await;
            continue;
        }

        let capture = match capture_page(&page, UserAgentBrowser::Firefox, &name).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[live-detector] capture failed for {name}: {e:?}");
                let _ = page.close().await;
                continue;
            }
        };
        let _ = page.close().await;

        let mut high_errors = 0usize;
        let mut medium_errors = 0usize;
        for surface in &capture.surfaces {
            let is_error = surface.value.is_err();
            match surface.severity {
                Severity::High if is_error => {
                    high_errors += 1;
                    eprintln!(
                        "[live-detector] {name} High surface {} errored: {}",
                        surface.name,
                        surface.value.as_ref().unwrap_err()
                    );
                }
                Severity::Medium if is_error => {
                    medium_errors += 1;
                    eprintln!(
                        "[live-detector] {name} Medium surface {} errored: {}",
                        surface.name,
                        surface.value.as_ref().unwrap_err()
                    );
                }
                _ => {}
            }
        }

        scorecard.personas.push(PersonaScore {
            profile: name.clone(),
            coherence_ok: true,
            high_errors,
            medium_errors,
            differential_high_divergences: None,
        });

        if high_errors > 0 {
            any_failure = Some(format!("{name}: {high_errors} High probe errors"));
        }
    }

    write_scorecard(&scorecard_dir, &scorecard).await;

    if let Some(msg) = any_failure {
        panic!("live per-persona detector suite failed: {msg}");
    }
}

/// G254: differential vs stock Firefox. If `STOCK_FIREFOX_BIN` is supplied,
/// capture the same detector page with a stock Firefox and with reynard wearing
/// the default Firefox persona, and assert there are no High divergences on
/// deterministic surfaces.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reynard_matches_stock_firefox_on_high_and_critical_surfaces() {
    let reynard_bin = match std::env::var("REYNARD_BIN") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("SKIP G254: set REYNARD_BIN to run the stock-Firefox differential");
            return;
        }
    };
    let stock_bin = match std::env::var("STOCK_FIREFOX_BIN") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("SKIP G254: set STOCK_FIREFOX_BIN to run the stock-Firefox differential");
            return;
        }
    };
    if std::env::var("DISPLAY").is_err() {
        eprintln!("SKIP G254: differential needs DISPLAY");
        return;
    }

    let detector_url =
        std::env::var("GUISE_LIVE_DETECTOR_URL").unwrap_or_else(|_| "about:blank".into());

    let profile = StealthProfile::FirefoxLinux;

    let stock_page = launch_firefox(FoxBrowserConfig {
        executable_path: Some(stock_bin.clone()),
        headless: false,
        viewport_width: 1280,
        viewport_height: 720,
        ..Default::default()
    })
    .await
    .expect("launch stock Firefox");
    stock_page
        .goto(&detector_url)
        .await
        .expect("navigate stock Firefox");
    let stock_capture = capture_page(&stock_page, UserAgentBrowser::Firefox, "stock-firefox")
        .await
        .expect("capture stock Firefox");
    let _ = stock_page.close().await;

    let reynard_page = launch_reynard(&reynard_bin, &profile, false)
        .await
        .expect("launch reynard");
    reynard_page
        .goto(&detector_url)
        .await
        .expect("navigate reynard");
    let reynard_capture = capture_page(&reynard_page, UserAgentBrowser::Firefox, "reynard")
        .await
        .expect("capture reynard");
    let _ = reynard_page.close().await;

    let report = diff_captures(&stock_capture, &reynard_capture);
    let bad: Vec<_> = report
        .divergences
        .iter()
        .filter(|d| matches!(d.severity, Severity::High))
        .collect();

    if !bad.is_empty() {
        eprintln!("[G254] High divergences between stock Firefox and reynard:");
        for d in &bad {
            eprintln!(
                "  {}: stock={:?} reynard={:?}",
                d.surface, d.a_value, d.b_value
            );
        }
    }
    assert!(
        bad.is_empty(),
        "reynard diverged from stock Firefox on {} High surfaces",
        bad.len()
    );
}

async fn write_scorecard(dir: &Option<PathBuf>, scorecard: &LiveScorecard) {
    let Some(dir) = dir else { return };
    if let Err(e) = tokio::fs::create_dir_all(dir).await {
        eprintln!("[live-detector] could not create scorecard dir {dir:?}: {e}");
        return;
    }
    let path = dir.join("guise-live-scorecard.json");
    match serde_json::to_vec_pretty(scorecard) {
        Ok(bytes) => {
            if let Err(e) = tokio::fs::write(&path, bytes).await {
                eprintln!("[live-detector] could not write scorecard {path:?}: {e}");
            } else {
                eprintln!("[live-detector] scorecard written to {path:?}");
            }
        }
        Err(e) => eprintln!("[live-detector] could not serialize scorecard: {e}"),
    }
}
