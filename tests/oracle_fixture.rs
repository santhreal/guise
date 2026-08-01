//! Offline differential-oracle fixture gate (G190).
//!
//! This test runs the oracle against a synthetic but representative captured-page
//! fixture instead of launching browsers. It proves the oracle's diffing,
//! rendering, and scorecard generation are deterministic and regression-locked
//! in CI without live-browser flakiness.
//!
//! The synthetic fixture models a stock Firefox vs a JS-disguise divergence set.
//! An operator can replace it with a real capture produced by
//! `guise::probe::capture_page` when running the live gate.
#![cfg(feature = "browser")]

use guise::fingerprint::{ProfileBundle, StealthProfile, UserAgentBrowser};
use guise::probe::{
    behavioral_capture, diff_captures, full_stack_compare, render_differential, render_three_way,
    scorecard_from_report, synthetic_firefox_fixture, three_way_compare, transport_capture,
    Scorecard,
};

#[test]
fn offline_oracle_fixture_produces_deterministic_report() {
    let (stock, disguise) = synthetic_firefox_fixture();
    let report = diff_captures(&stock, &disguise);

    // The fixture intentionally carries these divergences.
    let names: Vec<_> = report
        .divergences
        .iter()
        .map(|d| d.surface.as_str())
        .collect();
    assert!(names.contains(&"navigator.webdriver"));
    assert!(names.contains(&"navigator.hardwareConcurrency in [2, 16]"));
    assert!(names.contains(&"screen.width plausible"));
    assert!(names.contains(&"window.chrome.runtime exists"));
    assert!(names.contains(&"navigator.plugins.length > 0"));

    // Rendering is byte-identical across runs (G218).
    let r1 = render_differential(&report);
    let r2 = render_differential(&report);
    assert_eq!(r1, r2);
}

#[test]
fn offline_oracle_scorecard_serializes_and_prioritizes_critical() {
    let (stock, disguise) = synthetic_firefox_fixture();
    let report = diff_captures(&stock, &disguise);
    let scorecard = scorecard_from_report(&report, UserAgentBrowser::Firefox);

    // webdriver is Critical (100 points) and an engine tell → top fix.
    let fixes = scorecard.prioritized_fixes();
    assert!(!fixes.is_empty());
    assert_eq!(fixes[0].surface.surface_id, "navigator.webdriver");
    assert_eq!(fixes[0].benchmark_points, 100);

    // Round-trip through JSON keeps the schema intact.
    let json = serde_json::to_string(&scorecard).expect("serialize scorecard");
    let back: Scorecard = serde_json::from_str(&json).expect("deserialize scorecard");
    assert_eq!(
        back.schema_version,
        guise::probe::scorecard::SCORECARD_SCHEMA_VERSION
    );
    assert_eq!(back.lost_points, scorecard.lost_points);
    assert_eq!(back.entries, scorecard.entries);
}

#[test]
fn offline_oracle_fixture_identical_to_itself() {
    let (stock, _) = synthetic_firefox_fixture();
    let report = diff_captures(&stock, &stock);
    assert!(report.is_identical());
    assert!(scorecard_from_report(&report, UserAgentBrowser::Firefox).is_clean());
}

#[test]
fn offline_oracle_three_way_shows_engine_wins() {
    let (stock, disguise) = synthetic_firefox_fixture();
    // Model a patched reynard engine that matches stock on the engine-tell
    // surfaces (webdriver, chrome runtime, plugins) but still differs on the
    // persona-intended overrides (hardwareConcurrency, screen width).
    let mut reynard = stock.clone();
    reynard.label = "reynard".to_string();
    if let Some(s) = reynard
        .surfaces
        .iter_mut()
        .find(|s| s.name == "navigator.webdriver")
    {
        s.value = Ok("false".into());
    }
    if let Some(s) = reynard
        .surfaces
        .iter_mut()
        .find(|s| s.name == "window.chrome.runtime exists")
    {
        s.value = Ok("false".into());
    }
    if let Some(s) = reynard
        .surfaces
        .iter_mut()
        .find(|s| s.name == "navigator.plugins.length > 0")
    {
        s.value = Ok("3".into());
    }
    // Introduce a deliberate reynard regression on a surface the JS disguise
    // happens to get right (this produces a JS win for the three-way test).
    if let Some(s) = reynard
        .surfaces
        .iter_mut()
        .find(|s| s.name == "navigator.language")
    {
        s.value = Ok("\"en-GB\"".into());
    }

    let report = three_way_compare(&stock, &reynard, &disguise);
    eprintln!("\n{}", render_three_way(&report));

    // The engine wins on the cleaned-up tells.
    let engine_win_names: Vec<_> = report
        .engine_wins
        .iter()
        .map(|s| s.surface.as_str())
        .collect();
    assert!(engine_win_names.contains(&"navigator.webdriver"));
    assert!(engine_win_names.contains(&"window.chrome.runtime exists"));
    assert!(engine_win_names.contains(&"navigator.plugins.length > 0"));

    // The JS disguise wins on the surface we deliberately regressed in reynard
    // (reynard diverges from stock while the JS disguise matches stock).
    let js_win_names: Vec<_> = report.js_wins.iter().map(|s| s.surface.as_str()).collect();
    assert!(js_win_names.contains(&"navigator.language"));

    // Overall the patched engine is closer to stock than the JS disguise.
    assert!(report.engine_better_than_js());
}

#[test]
fn offline_full_stack_oracle_produces_one_scorecard() {
    // G206: full-stack oracle integration test combining JS, transport, and
    // behavioral layers into a single scorecard.
    let (stock_js, disguise_js) = synthetic_firefox_fixture();

    let stock_bundle = ProfileBundle::for_browser(StealthProfile::FirefoxLinux);
    let disguise_bundle = ProfileBundle::for_browser(StealthProfile::ChromeLinux);
    let stock_transport = transport_capture(&stock_bundle, "stock-firefox");
    let disguise_transport = transport_capture(&disguise_bundle, "disguise-chrome");

    let stock_behavioral = behavioral_capture(42, "stock-behavior");
    let disguise_behavioral = behavioral_capture(99, "disguise-behavior");

    let report = full_stack_compare(
        &stock_js,
        &stock_transport,
        &stock_behavioral,
        &disguise_js,
        &disguise_transport,
        &disguise_behavioral,
    );

    eprintln!("{}", report.summary());

    // The JS fixture intentionally diverges.
    assert!(!report.js.is_identical());
    // Transport diverges because Firefox vs Chrome TLS/H2 shapes differ.
    assert!(!report.transport.is_identical());
    // Behavioral diverges because the two seeds differ.
    assert!(!report.behavioral.is_identical());

    let scorecard = report.combined_scorecard(UserAgentBrowser::Firefox);
    assert!(!scorecard.is_clean());
    assert!(scorecard.lost_points > 0);
    assert!(scorecard.diverged >= 3);

    // Round-trip through JSON keeps the schema intact.
    let json = serde_json::to_string(&scorecard).expect("serialize scorecard");
    let back: Scorecard = serde_json::from_str(&json).expect("deserialize scorecard");
    assert_eq!(
        back.schema_version,
        guise::probe::scorecard::SCORECARD_SCHEMA_VERSION
    );
    assert_eq!(back.lost_points, scorecard.lost_points);
}

#[test]
fn fixture_capture_surfaces_are_unique_and_non_empty() {
    // G219: a capture produced by the oracle must contain at least one surface
    // and no duplicate names, even when evaluated concurrently over BiDi.
    let (stock, _) = synthetic_firefox_fixture();
    assert!(
        !stock.surfaces.is_empty(),
        "fixture must contain at least one surface"
    );

    let mut seen = std::collections::HashSet::new();
    for surface in &stock.surfaces {
        assert!(
            seen.insert(surface.name.as_str()),
            "duplicate surface {} in fixture",
            surface.name
        );
    }
}
