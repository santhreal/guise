use super::classify::*;
use super::*;

#[test]
fn catalogue_has_at_least_probe_count_floor_entries() {
    let list = probes();
    assert!(
        list.len() >= PROBE_COUNT_FLOOR,
        "probe catalogue has {} entries; floor is {}",
        list.len(),
        PROBE_COUNT_FLOOR
    );
}

#[test]
fn probe_names_are_unique() {
    let list = probes();
    let mut seen = std::collections::HashSet::new();
    for p in &list {
        assert!(seen.insert(p.name), "duplicate probe name: {}", p.name);
    }
}

#[test]
fn probe_severities_distributed() {
    let list = probes();
    let high = list.iter().filter(|p| p.severity == Severity::High).count();
    let medium = list
        .iter()
        .filter(|p| p.severity == Severity::Medium)
        .count();
    let low = list.iter().filter(|p| p.severity == Severity::Low).count();
    assert!(
        high >= 4,
        "expected at least 4 High-severity probes; got {high}"
    );
    assert!(
        medium >= 5,
        "expected at least 5 Medium-severity probes; got {medium}"
    );
    assert!(
        low >= 20,
        "expected at least 20 Low-severity probes; got {low}"
    );
}

#[test]
fn classify_webdriver_ok_pass_on_false_critical_on_true() {
    // A real browser reports navigator.webdriver === false (present, false).
    assert_eq!(
        classify_webdriver_ok(&serde_json::json!(false)),
        ProbeOutcome::Pass
    );
    // null (hidden) is leniently accepted...
    assert_eq!(
        classify_webdriver_ok(&serde_json::Value::Null),
        ProbeOutcome::Pass
    );
    // ...but true is the automation leak.
    match classify_webdriver_ok(&serde_json::json!(true)) {
        ProbeOutcome::Critical(_) => {}
        other => panic!("expected Critical for webdriver===true, got {other:?}"),
    }
}

#[test]
fn classify_must_be_undefined_pass_on_null() {
    assert_eq!(
        classify_must_be_undefined(&serde_json::Value::Null),
        ProbeOutcome::Pass
    );
}

#[test]
fn classify_must_be_undefined_critical_on_value() {
    match classify_must_be_undefined(&serde_json::json!(true)) {
        ProbeOutcome::Critical(_) => {}
        other => panic!("expected Critical, got {other:?}"),
    }
}

#[test]
fn classify_must_be_true_pass_on_true() {
    assert_eq!(
        classify_must_be_true(&serde_json::json!(true)),
        ProbeOutcome::Pass
    );
}

#[test]
fn classify_must_be_true_critical_on_false() {
    match classify_must_be_true(&serde_json::json!(false)) {
        ProbeOutcome::Critical(_) => {}
        other => panic!("expected Critical, got {other:?}"),
    }
}

#[test]
fn classify_must_be_chromium_ua_pass_on_real_chrome() {
    assert_eq!(
        classify_must_be_chromium_ua(&serde_json::json!(
            "Mozilla/5.0 (X11; Linux x86_64) Chrome/134.0.0.0 Safari/537.36"
        )),
        ProbeOutcome::Pass
    );
}

#[test]
fn classify_must_be_chromium_ua_passes_chromium_vendor_profiles() {
    for ua in [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 \
         (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/126.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0",
    ] {
        assert_eq!(
            classify_must_be_chromium_ua(&serde_json::json!(ua)),
            ProbeOutcome::Pass,
            "{ua}"
        );
    }
}

#[test]
fn classify_must_be_chromium_ua_critical_on_headless() {
    match classify_must_be_chromium_ua(&serde_json::json!("HeadlessChrome/134")) {
        ProbeOutcome::Critical(_) => {}
        other => panic!("expected Critical, got {other:?}"),
    }
}

#[test]
fn classify_must_be_chromium_ua_drifts_on_non_chromium_browser() {
    for ua in [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 \
         (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    ] {
        match classify_must_be_chromium_ua(&serde_json::json!(ua)) {
            ProbeOutcome::Drift(message) => assert!(
                message.contains("non-Chromium"),
                "unexpected drift message: {message}"
            ),
            other => panic!("expected Drift, got {other:?}"),
        }
    }
}

// ─── Family-aware catalogue (Lane B) ─────────────────────────────────────
// Two-pair: the Chromium catalogue measures against Chrome truth; the Firefox
// catalogue drops the Chromium-only surfaces (which a real Firefox legitimately
// lacks) and substitutes the matching Firefox truths.

#[test]
fn chromium_catalogue_keeps_chrome_only_surfaces() {
    let names: std::collections::HashSet<&str> = probes_for(UserAgentBrowser::Chrome)
        .iter()
        .map(|p| p.name)
        .collect();
    // Chrome truths are present...
    assert!(names.contains("window.chrome.runtime exists"));
    assert!(names.contains("navigator.vendor non-empty"));
    assert!(names.contains("navigator.usb exists"));
    assert!(names.contains("navigator.productSub equals '20030107'"));
    // ...and the Firefox-specific truths are NOT (Chrome would fail them).
    assert!(!names.contains("window.chrome absent (Firefox)"));
    assert!(!names.contains("navigator.vendor is empty (Firefox)"));
    // `probes()` is the back-compatible Chromium default.
    assert_eq!(probes().len(), probes_for(UserAgentBrowser::Chrome).len());
}

#[test]
fn firefox_catalogue_drops_chrome_only_and_adds_firefox_truths() {
    let names: std::collections::HashSet<&str> = probes_for(UserAgentBrowser::Firefox)
        .iter()
        .map(|p| p.name)
        .collect();
    // EVERY Chromium-only surface is dropped (none may survive for Firefox).
    for chrome_only in super::catalogue::CHROMIUM_ONLY_PROBES {
        assert!(
            !names.contains(chrome_only),
            "Firefox catalogue must not probe Chromium-only surface {chrome_only:?}"
        );
    }
    // The Firefox truths replace them.
    assert!(names.contains("window.chrome absent (Firefox)"));
    assert!(names.contains("navigator.vendor is empty (Firefox)"));
    assert!(names.contains("navigator.userAgent is Gecko/Firefox"));
    assert!(names.contains("navigator.usb absent (Firefox)"));
    assert!(names.contains("navigator.oscpu is a string (Firefox-only surface)"));
    // The extended-catalogue Chromium-only surfaces are dropped AND their inverse
    // "absent (Firefox)" assertions are present, a Firefox persona leaking a
    // Blink-only API (performance.memory et al.) is a Chromium-engine tell.
    assert!(!names.contains("memory jsHeapSizeLimit plausible"));
    assert!(!names.contains("navigator.keyboard exists"));
    assert!(!names.contains("EyeDropper exists"));
    assert!(names.contains("performance.memory absent (Firefox)"));
    assert!(names.contains("navigator.keyboard absent (Firefox)"));
    assert!(names.contains("window.EyeDropper absent (Firefox)"));
}

/// Durable guard for the WIRING bug class behind the extended-catalogue leak: a
/// probe that asserts the PRESENCE of a Chromium-only surface
/// (`classify_must_be_true`) must never survive into the Firefox catalogue, where
/// it would Critical on every real Gecko build. The earlier
/// `firefox_catalogue_drops_chrome_only_and_adds_firefox_truths` check could not
/// catch this: it only re-checks names ALREADY in `CHROMIUM_ONLY_PROBES`, so a
/// Chromium-only surface that was never registered there (exactly how the extended
/// catalogue's `performance.memory`/`navigator.keyboard`/… leaked) passed
/// vacuously. This guard inspects the actual Firefox catalogue: any presence-probe
/// whose JS references a known Blink-only global is a regression.
#[test]
fn firefox_catalogue_has_no_chromium_only_presence_probe() {
    // Blink/Chromium-only globals a real Gecko build never exposes. A
    // `classify_must_be_true` probe testing one of these is a false-Critical on
    // Firefox. (The inverse `… absent (Firefox)` probes also name these tokens but
    // classify with `classify_must_be_undefined`, so the classifier filter below
    // excludes them.)
    const CHROMIUM_ONLY_GLOBAL_TOKENS: &[&str] = &[
        "performance.memory",
        "navigator.keyboard",
        "navigator.presentation",
        "navigator.scheduling",
        "setAppBadge",
        "clearAppBadge",
        // NB: `documentPictureInPicture` is intentionally NOT here. Firefox 151
        // ships it in a secure context (verified live), so it is not a
        // Chromium-only global. WebGPU (`navigator.gpu`) is likewise omitted: it is
        // engine-conditional (Firefox Windows has it), not Chromium-only. Both are
        // dropped for the Firefox gate via CHROMIUM_ONLY_PROBES category 2 instead.
        "EyeDropper",
        "BarcodeDetector",
        "FaceDetector",
        "AbsoluteOrientationSensor",
        "window.chrome",
        "navigator.usb",
        "navigator.hid",
        "ReportingObserver",
    ];
    for p in probes_for(UserAgentBrowser::Firefox) {
        if !std::ptr::fn_addr_eq(
            p.classifier,
            classify_must_be_true as fn(&serde_json::Value) -> ProbeOutcome,
        ) {
            continue; // only PRESENCE assertions can false-Critical on absence
        }
        for token in CHROMIUM_ONLY_GLOBAL_TOKENS {
            assert!(
                !p.js.contains(token),
                "Firefox catalogue presence-probe {:?} tests Chromium-only global {token:?} \
It will report Critical on every real Gecko build. Drop it via \
                 CHROMIUM_ONLY_PROBES and add an inverse `… absent (Firefox)` probe.",
                p.name
            );
        }
    }
}

/// Engine-conditional surfaces (WebGPU, Document Picture-in-Picture) must be
/// DROPPED for the Firefox gate, verified live (tests/surface_truth_live.rs) that
/// FF-151-Linux lacks WebGPU yet ships Document PiP, so a `classify_must_be_true`
/// presence check false-Criticals guise's OWN browser and an "absent" inverse
/// false-Criticals Firefox Windows. They must still be present in the Chrome
/// reference catalogue (modern desktop Chrome exposes the API surface), so this is
/// a family-aware drop, not a deletion.
#[test]
fn engine_conditional_surfaces_dropped_for_firefox_kept_for_chrome() {
    const CONDITIONAL: &[&str] = &[
        "navigator.gpu exists",
        "navigator.gpu.requestAdapter is function",
        "GPUAdapter.limits is object",
        "GPUBufferUsage exists",
        "navigator.gpu.getPreferredCanvasFormat exists",
        "DocumentPictureInPicture exists",
        // OS/environment-conditional (headless/Linux Firefox legitimately has 0 TTS
        // voices); dropped for the Firefox gate, kept in the Chrome reference.
        "speechSynthesis.getVoices returns >=16 voices",
    ];
    let chrome: std::collections::HashSet<&str> = probes().iter().map(|p| p.name).collect();
    let firefox: std::collections::HashSet<&str> = probes_for(UserAgentBrowser::Firefox)
        .iter()
        .map(|p| p.name)
        .collect();

    for name in CONDITIONAL {
        assert!(
            chrome.contains(name),
            "conditional surface {name:?} must stay in the Chrome reference catalogue"
        );
        assert!(
            !firefox.contains(name),
            "conditional surface {name:?} must be DROPPED for the Firefox gate \
             (it false-Criticals guise's own Firefox)"
        );
    }

    // No probe of ANY kind may assert a WebGPU or Document-PiP truth for Firefox
    // neither a presence check nor a stray "absent" inverse, because the surface
    // is engine-conditional in BOTH directions on Firefox.
    for p in probes_for(UserAgentBrowser::Firefox) {
        let n = p.name;
        assert!(
            !n.contains("gpu") && !n.contains("GPU") && !n.contains("DocumentPictureInPicture"),
            "Firefox catalogue must not assert engine-conditional surface {n:?}"
        );
    }
}

#[test]
fn firefox_catalogue_probe_names_unique() {
    let list = probes_for(UserAgentBrowser::Firefox);
    let mut seen = std::collections::HashSet::new();
    for p in &list {
        assert!(
            seen.insert(p.name),
            "duplicate probe name in firefox catalogue: {}",
            p.name
        );
    }
}

#[test]
fn classify_empty_string_pass_on_empty_critical_on_value() {
    assert_eq!(
        classify_must_be_empty_string(&serde_json::json!("")),
        ProbeOutcome::Pass
    );
    match classify_must_be_empty_string(&serde_json::json!("Google Inc.")) {
        ProbeOutcome::Critical(_) => {}
        other => panic!("expected Critical for non-empty vendor, got {other:?}"),
    }
}

#[test]
fn classify_nonzero_int_boundary_at_zero_and_one() {
    assert_eq!(
        classify_must_be_nonzero_int(&serde_json::json!(1)),
        ProbeOutcome::Pass
    );
    match classify_must_be_nonzero_int(&serde_json::json!(0)) {
        ProbeOutcome::Critical(_) => {}
        other => panic!("expected Critical for 0, got {other:?}"),
    }
    match classify_must_be_nonzero_int(&serde_json::Value::Null) {
        ProbeOutcome::Drift(_) => {}
        other => panic!("expected Drift for null, got {other:?}"),
    }
}

#[test]
fn classify_firefox_ua_pass_on_gecko_critical_on_chrome() {
    assert_eq!(
        classify_must_be_firefox_ua(&serde_json::json!(
            "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
        )),
        ProbeOutcome::Pass
    );
    match classify_must_be_firefox_ua(&serde_json::json!(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
    )) {
        ProbeOutcome::Critical(_) => {}
        other => panic!("expected Critical for a Chrome UA, got {other:?}"),
    }
}

#[test]
fn classify_iana_timezone_pass_on_real_zones() {
    for tz in [
        "America/Phoenix",
        "Europe/London",
        "Etc/GMT+5",
        "America/Argentina/Buenos_Aires",
        "UTC",
    ] {
        assert_eq!(
            classify_iana_timezone(&serde_json::json!(tz)),
            ProbeOutcome::Pass,
            "{tz}"
        );
    }
}

#[test]
fn classify_iana_timezone_critical_on_empty_drift_on_garbage() {
    // An empty resolved zone is the stripped-ICU / headless tell → Critical.
    match classify_iana_timezone(&serde_json::json!("")) {
        ProbeOutcome::Critical(m) => assert!(m.contains("EMPTY")),
        other => panic!("expected Critical for empty tz, got {other:?}"),
    }
    // A non-IANA-shaped string is unusual but not a definitive bot → Drift. We do
    // NOT pin a specific zone (the persona has no timezone field), so a bareword
    // without a region is malformed, not "wrong zone".
    for bad in ["notazone", "America/", "/Phoenix", "Foo//Bar", "Etc/GMT 5"] {
        match classify_iana_timezone(&serde_json::json!(bad)) {
            ProbeOutcome::Drift(_) => {}
            other => panic!("expected Drift for {bad:?}, got {other:?}"),
        }
    }
    // Non-string → Drift, never a silent pass.
    match classify_iana_timezone(&serde_json::Value::Null) {
        ProbeOutcome::Drift(_) => {}
        other => panic!("expected Drift for null tz, got {other:?}"),
    }
}

#[test]
fn classify_must_not_contain_swiftshader_critical_on_match() {
    match classify_must_not_contain_swiftshader(&serde_json::json!("Google Inc. (SwiftShader)")) {
        ProbeOutcome::Critical(_) => {}
        other => panic!("expected Critical, got {other:?}"),
    }
}

#[test]
fn drift_report_is_green_when_passed_meets_floor() {
    let report = DriftReport {
        probed: 100,
        passed: 95,
        drift: 5,
        critical: 0,
        probe_errors: 0,
        per_probe: vec![],
    };
    assert!(report.is_green());
}

#[test]
fn drift_report_is_not_green_with_critical() {
    let report = DriftReport {
        probed: 100,
        passed: 99,
        drift: 0,
        critical: 1,
        probe_errors: 0,
        per_probe: vec![],
    };
    assert!(!report.is_green());
}

#[test]
fn drift_report_is_not_green_when_passed_under_floor() {
    let report = DriftReport {
        probed: 100,
        passed: 80,
        drift: 20,
        critical: 0,
        probe_errors: 0,
        per_probe: vec![],
    };
    assert!(!report.is_green());
}

#[test]
fn classify_user_agent_data_empty_or_absent_passes_for_firefox_truth() {
    use super::classify::classify_user_agent_data_empty_or_absent;
    assert_eq!(
        classify_user_agent_data_empty_or_absent(&serde_json::Value::Null),
        ProbeOutcome::Pass
    );
    assert_eq!(
        classify_user_agent_data_empty_or_absent(&serde_json::json!([])),
        ProbeOutcome::Pass
    );
}

#[test]
fn classify_user_agent_data_empty_or_absent_critical_on_chromium_brands() {
    use super::classify::classify_user_agent_data_empty_or_absent;
    match classify_user_agent_data_empty_or_absent(&serde_json::json!([
        {"brand": "Chromium", "version": "131"},
        {"brand": "Google Chrome", "version": "131"}
    ])) {
        ProbeOutcome::Critical(m) => assert!(m.contains("Client Hints brands")),
        other => panic!("expected Critical, got {other:?}"),
    }
}

#[test]
fn hardware_concurrency_probe_catches_gap_values_from_tests_gap_rs() {
    // G211: the static validate_overrides gap says out-of-range values pass
    // validation, but the runtime catalogue probe continuously catches them.
    assert!(!classify_hardware_concurrency(&serde_json::json!(0)).is_pass());
    assert!(!classify_hardware_concurrency(&serde_json::json!(10000)).is_pass());
}

#[test]
fn firefox_catalogue_has_user_agent_data_probe() {
    let names: std::collections::HashSet<&str> = probes_for(UserAgentBrowser::Firefox)
        .iter()
        .map(|p| p.name)
        .collect();
    assert!(
        names.contains("navigator.userAgentData absent or brands empty (Firefox)"),
        "G211 gap converted to a Firefox-family catalogue probe"
    );
}

#[test]
fn render_report_includes_summary() {
    let report = DriftReport {
        probed: 5,
        passed: 5,
        drift: 0,
        critical: 0,
        probe_errors: 0,
        per_probe: vec![ProbeReport {
            name: "test_probe".to_string(),
            severity: "Low".to_string(),
            outcome: ProbeOutcome::Pass,
        }],
    };
    let rendered = render_report(&report);
    assert!(rendered.contains("STEALTH PROBE"));
    assert!(rendered.contains("test_probe"));
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 10_000, .. proptest::test_runner::Config::default()
    })]

    #[test]
    fn prop_classify_in_range_consistent(
        n in 0u64..1_000_000,
        min in 0u64..1000,
        max in 1000u64..10_000,
    ) {
        let outcome = classify_in_range(&serde_json::json!(n), min, max);
        if (min..=max).contains(&n) {
            assert_eq!(outcome, ProbeOutcome::Pass);
        } else {
            match outcome {
                ProbeOutcome::Drift(_) => {},
                other => panic!("expected Drift, got {other:?}"),
            }
        }
    }

    #[test]
    fn prop_render_report_does_not_panic(probed in 0usize..1000, passed in 0usize..1000) {
        let report = DriftReport {
            probed,
            passed: passed.min(probed),
            drift: 0,
            critical: 0,
            probe_errors: 0,
            per_probe: vec![],
        };
        let _ = render_report(&report);
    }
}
