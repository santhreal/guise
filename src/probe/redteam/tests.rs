//! Unit tests for [`super`] (the red-team self-probe detectors).

use super::*;
use serde_json::json;

#[test]
fn redteam_set_is_nonempty_and_uniquely_named() {
    let p = redteam_probes();
    assert!(p.len() >= 7, "expected the full red-team set");
    let mut names: Vec<&str> = p.iter().map(|x| x.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), p.len(), "probe names must be unique");
    // Every probe carries non-empty JS.
    assert!(p.iter().all(|x| !x.js.is_empty()));
}

#[test]
fn timing_surfaces_are_stochastic_others_deterministic() {
    // The two entropy/scheduler-driven surfaces MUST be Stochastic so the
    // differential oracle compares them by outcome class, otherwise machine
    // noise (busy-loop CV 4.36 vs 3.00, both Pass) is a false divergence. Every
    // other red-team surface is a reproducible identity/coherence check.
    for p in redteam_probes() {
        let want =
            if p.name.contains("busy-loop timing") || p.name.contains("high-resolution timer") {
                Determinism::Stochastic
            } else {
                Determinism::Deterministic
            };
        assert_eq!(p.determinism, want, "wrong determinism for {:?}", p.name);
    }
}

#[test]
fn outcome_class_label_is_payload_independent() {
    // Two Drifts with different explanations share a class, the property the
    // oracle relies on to treat stochastic surfaces as agreeing.
    assert_eq!(ProbeOutcome::Pass.class_label(), "Pass");
    assert_eq!(ProbeOutcome::Drift("a".into()).class_label(), "Drift");
    assert_eq!(ProbeOutcome::Drift("b".into()).class_label(), "Drift");
    assert_eq!(ProbeOutcome::Critical("x".into()).class_label(), "Critical");
    assert_eq!(
        ProbeOutcome::ProbeError("e".into()).class_label(),
        "ProbeError"
    );
}

#[test]
fn timing_cv_pass_drift_critical_boundaries() {
    assert_eq!(classify_timing_cv(&json!(0.25)), ProbeOutcome::Pass);
    assert_eq!(classify_timing_cv(&json!(0.10)), ProbeOutcome::Pass);
    assert!(matches!(
        classify_timing_cv(&json!(0.05)),
        ProbeOutcome::Drift(_)
    ));
    assert!(matches!(
        classify_timing_cv(&json!(0.01)),
        ProbeOutcome::Critical(_)
    ));
    assert!(matches!(
        classify_timing_cv(&json!(-1)),
        ProbeOutcome::Critical(_)
    ));
    assert!(matches!(
        classify_timing_cv(&json!("x")),
        ProbeOutcome::ProbeError(_)
    ));
}

#[test]
fn missing_apis_thresholds() {
    assert_eq!(classify_missing_apis(&json!(0)), ProbeOutcome::Pass);
    assert!(matches!(
        classify_missing_apis(&json!(2)),
        ProbeOutcome::Drift(_)
    ));
    assert!(matches!(
        classify_missing_apis(&json!(5)),
        ProbeOutcome::Critical(_)
    ));
    assert!(matches!(
        classify_missing_apis(&json!("x")),
        ProbeOutcome::ProbeError(_)
    ));
}

#[test]
fn automation_globals_empty_passes_nonempty_critical() {
    assert_eq!(classify_automation_globals(&json!([])), ProbeOutcome::Pass);
    match classify_automation_globals(&json!(["navigator.webdriver", "cdc_foo"])) {
        ProbeOutcome::Critical(m) => {
            assert!(m.contains("navigator.webdriver") && m.contains("cdc_foo"))
        }
        o => panic!("expected Critical, got {o:?}"),
    }
    assert!(matches!(
        classify_automation_globals(&json!("nope")),
        ProbeOutcome::ProbeError(_)
    ));
}

#[test]
fn document_all_quirk() {
    assert_eq!(
        classify_document_all(&json!("undefined")),
        ProbeOutcome::Pass
    );
    assert!(matches!(
        classify_document_all(&json!("object")),
        ProbeOutcome::Critical(_)
    ));
    assert!(matches!(
        classify_document_all(&json!(1)),
        ProbeOutcome::ProbeError(_)
    ));
}

#[test]
fn timer_resolution_outcomes() {
    // A positive granularity (e.g. Firefox's 1ms reduceTimerPrecision clamp) is a
    // healthy timer: Pass. -1 (missing) is the strong sandbox tell. Critical. 0
    // (never advances even under sustained work) is a frozen timer. Drift.
    assert_eq!(classify_timer_resolution(&json!(1.0)), ProbeOutcome::Pass);
    assert_eq!(classify_timer_resolution(&json!(0.05)), ProbeOutcome::Pass);
    assert!(matches!(
        classify_timer_resolution(&json!(-1)),
        ProbeOutcome::Critical(_)
    ));
    assert!(matches!(
        classify_timer_resolution(&json!(0.0)),
        ProbeOutcome::Drift(_)
    ));
    assert!(matches!(
        classify_timer_resolution(&json!("x")),
        ProbeOutcome::ProbeError(_)
    ));
}

#[test]
fn timer_resolution_js_does_work_between_reads_not_a_tight_loop() {
    // The probe MUST do work between performance.now() reads and spin until the
    // timer advances. A tight loop of bare reads returns 0 on every modern browser
    // (reduceTimerPrecision / cross-origin clamp), verified live that a BARE
    // Firefox reports 0 for a tight loop but advances once work runs. Guard against
    // regressing to the tight-read form that false-Drifts every real browser.
    let js = super::TIMER_RESOLUTION_JS;
    assert!(
        js.contains("performance.now"),
        "probe must read performance.now"
    );
    // An inner work loop (busy iteration) must sit between the timer reads.
    assert!(
        js.contains("for(var j=0") && js.contains("while("),
        "timer probe must spin with work between reads, not tight-read: {js}"
    );
    // The pre-clamp tight-read shape pushed per-iteration deltas into an array.
    assert!(
        !js.contains("deltas.push"),
        "timer probe regressed to the tight-read delta-array form that false-drifts \
         clamped (privacy-hardened) browsers"
    );
}

#[test]
fn fp_api_coherence_firefox_leaking_blink_api_is_critical() {
    // Firefox UA but WebUSB present → capability set betrays Blink.
    let v = json!({
        "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0",
        "usb": true, "hid": false, "serial": false, "bluetooth": false,
        "getBattery": false, "mediaDevices": true
    });
    match classify_fp_api_coherence(&v) {
        ProbeOutcome::Critical(m) => assert!(m.contains("navigator.usb"), "{m}"),
        o => panic!("expected Critical, got {o:?}"),
    }
}

#[test]
fn fp_api_coherence_clean_firefox_passes() {
    let v = json!({
        "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0",
        "usb": false, "hid": false, "serial": false, "bluetooth": false,
        "getBattery": false, "mediaDevices": true
    });
    assert_eq!(classify_fp_api_coherence(&v), ProbeOutcome::Pass);
}

#[test]
fn fp_api_coherence_firefox_with_web_serial_passes() {
    // Regression guard for the stale-model fix: a vanilla, non-automated Firefox
    // 151 on a secure origin exposes `navigator.serial` (a live object. Firefox
    // ships Web Serial in secure contexts). serial is NO LONGER a Blink-only
    // surface, so a real Firefox advertising it MUST pass, flagging it was the
    // false critical that broke the live probe gate. The genuinely Blink-only
    // surfaces (usb/hid/bluetooth/getBattery) stay absent.
    let v = json!({
        "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0",
        "usb": false, "hid": false, "serial": true, "bluetooth": false,
        "getBattery": false, "mediaDevices": true
    });
    assert_eq!(classify_fp_api_coherence(&v), ProbeOutcome::Pass);
}

#[test]
fn fp_api_coherence_firefox_without_mediadevices_drifts() {
    let v = json!({
        "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0",
        "usb": false, "hid": false, "serial": false, "bluetooth": false,
        "getBattery": false, "mediaDevices": false
    });
    assert!(matches!(
        classify_fp_api_coherence(&v),
        ProbeOutcome::Drift(_)
    ));
}

#[test]
fn fp_api_coherence_chrome_with_blink_apis_passes() {
    let v = json!({
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "usb": true, "hid": true, "serial": true, "bluetooth": true,
        "getBattery": true, "mediaDevices": true
    });
    assert_eq!(classify_fp_api_coherence(&v), ProbeOutcome::Pass);
}

#[test]
fn fp_api_coherence_stripped_chrome_drifts() {
    let v = json!({
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "usb": false, "hid": false, "serial": false, "bluetooth": false,
        "getBattery": false, "mediaDevices": true
    });
    assert!(matches!(
        classify_fp_api_coherence(&v),
        ProbeOutcome::Drift(_)
    ));
}

#[test]
fn fp_api_coherence_missing_ua_is_probe_error() {
    assert!(matches!(
        classify_fp_api_coherence(&json!({"usb": false})),
        ProbeOutcome::ProbeError(_)
    ));
}

const FF_UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0";
const CR_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

#[test]
fn error_coherence_clean_firefox_passes() {
    // Real Gecko: no V8 Error members, '@'-style frames.
    let v = json!({
        "ua": FF_UA, "captureStackTrace": false, "stackTraceLimit": false,
        "prepareStackTrace": false, "stackShape": "gecko"
    });
    assert_eq!(classify_error_engine_coherence(&v), ProbeOutcome::Pass);
}

#[test]
fn error_coherence_firefox_with_capturestacktrace_alone_passes() {
    // Regression guard for the stale-model fix: a vanilla, non-automated
    // Firefox 151 exposes `Error.captureStackTrace` (a live function, shipped in
    // FF-122 for V8 compat) while `stackTraceLimit`/`prepareStackTrace` stay
    // undefined and frames are Gecko-style. captureStackTrace is therefore NO
    // LONGER a V8 discriminator, and this real-Firefox shape MUST pass, flagging
    // it was the false critical that broke the live probe gate.
    let v = json!({
        "ua": FF_UA, "captureStackTrace": true, "stackTraceLimit": false,
        "prepareStackTrace": false, "stackShape": "gecko"
    });
    assert_eq!(classify_error_engine_coherence(&v), ProbeOutcome::Pass);
}

#[test]
fn error_coherence_firefox_with_v8_stacktracelimit_is_critical() {
    // `Error.stackTraceLimit` IS still V8-only (undefined on real FF-151), so a
    // Firefox persona exposing it is genuinely running on V8.
    let v = json!({
        "ua": FF_UA, "captureStackTrace": true, "stackTraceLimit": true,
        "prepareStackTrace": false, "stackShape": "gecko"
    });
    match classify_error_engine_coherence(&v) {
        ProbeOutcome::Critical(m) => assert!(m.contains("Error.stackTraceLimit"), "{m}"),
        o => panic!("expected Critical, got {o:?}"),
    }
}

#[test]
fn error_coherence_firefox_with_v8_stack_shape_is_critical() {
    // No V8 members, but Chrome-style '    at ' frames → engine mismatch.
    let v = json!({
        "ua": FF_UA, "captureStackTrace": false, "stackTraceLimit": false,
        "prepareStackTrace": false, "stackShape": "v8"
    });
    assert!(matches!(
        classify_error_engine_coherence(&v),
        ProbeOutcome::Critical(_)
    ));
}

#[test]
fn error_coherence_real_chrome_passes() {
    let v = json!({
        "ua": CR_UA, "captureStackTrace": true, "stackTraceLimit": true,
        "prepareStackTrace": true, "stackShape": "v8"
    });
    assert_eq!(classify_error_engine_coherence(&v), ProbeOutcome::Pass);
}

#[test]
fn error_coherence_chrome_without_capturestacktrace_drifts() {
    let v = json!({
        "ua": CR_UA, "captureStackTrace": false, "stackTraceLimit": false,
        "prepareStackTrace": false, "stackShape": "v8"
    });
    assert!(matches!(
        classify_error_engine_coherence(&v),
        ProbeOutcome::Drift(_)
    ));
}

#[test]
fn error_coherence_firefox_no_stack_captured_passes() {
    // A throw that yields no stack ('none') is acceptable for Gecko, the
    // probe must not manufacture a tell from a missing stack.
    let v = json!({
        "ua": FF_UA, "captureStackTrace": false, "stackTraceLimit": false,
        "prepareStackTrace": false, "stackShape": "none"
    });
    assert_eq!(classify_error_engine_coherence(&v), ProbeOutcome::Pass);
}

#[test]
fn error_coherence_missing_ua_is_probe_error() {
    assert!(matches!(
        classify_error_engine_coherence(&json!({"captureStackTrace": false})),
        ProbeOutcome::ProbeError(_)
    ));
}

#[test]
fn iframe_contentwindow_native_string_passes() {
    assert_eq!(
        classify_must_be_native_code(&json!(
            "function get contentWindow() {\n    [native code]\n}"
        )),
        ProbeOutcome::Pass
    );
}

#[test]
fn iframe_contentwindow_wrapped_string_critical() {
    match classify_must_be_native_code(&json!("function() { return {}; }")) {
        ProbeOutcome::Critical(_) => {}
        other => panic!("expected Critical for wrapped getter, got {other:?}"),
    }
}

#[test]
fn permissions_query_native_string_passes() {
    assert_eq!(
        classify_must_be_native_code(&json!("function query() {\n    [native code]\n}")),
        ProbeOutcome::Pass
    );
}

#[test]
fn redteam_probe_list_contains_new_native_code_probes() {
    let names: std::collections::HashSet<&str> = redteam_probes().iter().map(|p| p.name).collect();
    assert!(names.contains("redteam: HTMLIFrameElement.contentWindow getter is native code"));
    assert!(names.contains("redteam: Permissions.prototype.query is native code"));
}
