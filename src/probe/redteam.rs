//! Red-team probes derived from the Santh `sear` detonation engine's adversarial
//! sandbox-detection PoCs (`detonation/sear/tests/adversarial_sandbox_detection.rs`).
//!
//! sear wrote these as a *detector*: JavaScript that decides "am I being analysed
//! in a sandbox / by automation?". **Inverted for stealth**, each becomes a probe
//! a genuinely human browser must PASS, a real, stealthed Chrome must always
//! look like `REAL_BROWSER`, never `SANDBOX_DETECTED`. This is the red-vs-blue
//! self-test the consolidation plan calls for, sourced from our OWN detection
//! engine rather than a public anti-bot library, a capability no off-the-shelf
//! stealth crate has.
//!
//! Every classifier here is pure (`fn(&serde_json::Value) -> ProbeOutcome`) and
//! unit-tested below; the JS runs against a live `runtime_foxdriver` Firefox
//! `Page` over WebDriver-BiDi via [`super::run`].

use super::classify::classify_must_be_native_code;
use super::{Determinism, Probe, ProbeOutcome, Severity};

/// Busy-loop timing coefficient-of-variation. A real browser on a real OS
/// scheduler shows jitter (CV ≳ 0.1); an instrumented or over-precise timer, a
/// sandbox tell sear exploits, collapses toward zero. Returns the CV, or `-1`
/// if the loop took 0 ms total (suspiciously instant).
const TIMING_CV_JS: &str = "(function(){var m=[];for(var i=0;i<20;i++){var s=Date.now();var x=0;for(var j=0;j<100000;j++){x+=j;}m.push(Date.now()-s);}var n=m.length;var mean=m.reduce(function(a,b){return a+b;},0)/n;if(mean<=0)return -1;var v=m.reduce(function(a,b){return a+(b-mean)*(b-mean);},0)/n;return Math.sqrt(v)/mean;})()";

/// Count of standard web-platform APIs that are ABSENT. A real Chrome has all of
/// them; sear's sandbox (and most headless/instrumented envs) is missing several.
const MISSING_APIS_JS: &str = "(function(){var c=0;if(typeof RTCPeerConnection==='undefined')c++;if(typeof indexedDB==='undefined')c++;if(typeof Notification==='undefined')c++;if(!(typeof navigator!=='undefined'&&'serviceWorker' in navigator))c++;if(!(typeof navigator!=='undefined'&&'mediaDevices' in navigator))c++;try{var cv=document.createElement('canvas');if(!cv.getContext('webgl')&&!cv.getContext('experimental-webgl'))c++;}catch(e){c++;}return c;})()";

/// Names of any automation-framework globals present on `window` (plus
/// `navigator.webdriver === true`). A real, stealthed browser leaks NONE.
const AUTOMATION_GLOBALS_JS: &str = "(function(){var leaks=[];var w=window;['__nightmare','_phantom','__phantomas','callPhantom','_selenium','__selenium_unwrapped','__webdriver_evaluate','__driver_evaluate','__webdriver_script_fn','__fxdriver_evaluate','__playwright','__puppeteer','domAutomation','domAutomationController'].forEach(function(k){try{if(typeof w[k]!=='undefined')leaks.push(k);}catch(e){}});try{for(var k in w){if(/^\\$?cdc_|^\\$?chrome_asyncScriptInfo|webdriver/i.test(k))leaks.push(k);}}catch(e){}try{if(navigator.webdriver===true)leaks.push('navigator.webdriver');}catch(e){}return leaks;})()";

/// `typeof document.all`. The HTML spec's `[[IsHTMLDDA]]` legacy slot makes a
/// real browser return the string `"undefined"` here; a naive shim that recreates
/// `document.all` as an ordinary object returns `"object"` and gives itself away.
const DOCUMENT_ALL_JS: &str = "(typeof document.all)";

/// First positive `performance.now()` delta once the timer advances under
/// sustained work. `-1` means `performance.now` is missing entirely (a strong
/// sandbox tell sear's timer-entropy PoC keys on); `0` means it NEVER advanced
/// even after sustained work (a genuinely frozen/virtualized timer).
///
/// A naive tight read loop is WRONG here: every modern browser coarsens the timer
/// for privacy: Firefox's `privacy.reduceTimerPrecision` clamps `performance.now`
/// to ~1ms by default (Chrome similarly clamps outside cross-origin isolation), so
/// a tight loop of bare reads finishes inside one clamp window and reports `0` on a
/// perfectly healthy timer. Verified live: a BARE, un-stealthed Firefox returns
/// `0` for a tight loop but advances to `1` once real work runs between reads
/// (`tests/surface_truth_live.rs`). So we do work between reads and spin (bounded)
/// until the timer ticks: a real timer advances within a few hundred iterations; a
/// frozen one never does. This distinguishes privacy-clamping (normal) from a
/// frozen sandbox timer (a tell) instead of false-flagging every real browser.
const TIMER_RESOLUTION_JS: &str = "(function(){if(typeof performance==='undefined'||typeof performance.now!=='function')return -1;var start=performance.now();var now=start;var iters=0;while(now===start&&iters<2000000){var x=0;for(var j=0;j<50;j++){x+=j;}now=performance.now();iters++;}return now-start;})()";

/// UA-vs-modern-fingerprinting-API coherence. Returns the UA plus presence of the
/// surfaces sear's `fingerprint.rs` instruments (the APIs real anti-bot WAFs
/// probe). The set of present APIs is itself a fingerprint: WebUSB/WebHID/Web
/// Serial/Web Bluetooth and `getBattery` are **Chromium-only**: a real Firefox
/// exposes NONE of them. A "Firefox" persona that leaks any is incoherent (UA
/// says Gecko, capability set says Blink). guise's family catalogue merely DROPS
/// these probes for Firefox; it never asserts their ABSENCE, so an accidental
/// leak sails through. This probe closes that gap.
const FP_API_COHERENCE_JS: &str = "(function(){var n=navigator;function has(o,k){try{return k in o;}catch(e){return false;}}return {ua:n.userAgent,usb:has(n,'usb'),hid:has(n,'hid'),serial:has(n,'serial'),bluetooth:has(n,'bluetooth'),getBattery:has(n,'getBattery'),mediaDevices:has(n,'mediaDevices'),storageEstimate:!!(n.storage&&n.storage.estimate),share:has(n,'share'),wakeLock:has(n,'wakeLock'),xr:has(n,'xr')};})()";

/// UA-vs-**error-subsystem** coherence, the CodePath/ErrorMessage analog of the
/// capability probe, sourced from sear's differential divergence kinds. Two tells
/// that value-diffing the *normal* surfaces never sees:
///   1. `Error.captureStackTrace` / `Error.stackTraceLimit` / `prepareStackTrace`
///      are **V8-only**: a genuine Gecko build exposes NONE. A "Firefox" persona
///      that has them is running on V8 (or was shimmed by a Blink-shaped harness).
///   2. Stack-frame *framing* differs by engine: V8 renders `    at fn (url:1:2)`,
///      Gecko renders `fn@url:1:2`. A Firefox UA with `at`-style frames is a hard
///      engine mismatch. This is exactly where JS overrides leak, they fake the
///      values a page reads but cannot change how the engine formats a throw.
const ERROR_ENGINE_COHERENCE_JS: &str = "(function(){var n=navigator;function has(o,k){try{return typeof o[k]!=='undefined';}catch(e){return false;}}var stk='';try{throw new Error('probe');}catch(e){stk=String((e&&e.stack)||'');}var shape=/(?:^|\\n)\\s+at\\s/.test(stk)?'v8':(/@/.test(stk)?'gecko':'none');return {ua:n.userAgent,captureStackTrace:has(Error,'captureStackTrace'),stackTraceLimit:has(Error,'stackTraceLimit'),prepareStackTrace:has(Error,'prepareStackTrace'),stackShape:shape};})()";

/// `HTMLIFrameElement.prototype.contentWindow` getter must be native code. Anti-bot
/// evasions often wrap this getter to sanitize the framed window object; the
/// wrapper's `toString` then leaks `[object Object]` or the wrapper source.
const IFRAME_CONTENTWINDOW_JS: &str = "(function(){try{var d=Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype,'contentWindow');return d&&typeof d.get==='function'?Function.prototype.toString.call(d.get):'NO_GETTER';}catch(e){return String(e);}})()";

/// `Permissions.prototype.query` must be native code. A common automation-hiding
/// wrapper intercepts permission queries (notifications, midi, etc.) and returns
/// hard-coded `prompt`/`granted` answers; the wrapper's toString is a tell.
const PERMISSIONS_QUERY_JS: &str = "(function(){try{var d=Object.getOwnPropertyDescriptor(Permissions.prototype,'query');return d&&typeof d.value==='function'?Function.prototype.toString.call(d.value):'NO_VALUE';}catch(e){return String(e);}})()";

/// The sear-derived red-team probe set. Folded into [`super::catalogue::probes`].
pub(super) fn redteam_probes() -> Vec<Probe> {
    vec![
        Probe {
            name: "redteam(sear): busy-loop timing shows human scheduler jitter",
            js: TIMING_CV_JS,
            severity: Severity::Medium,
            classifier: classify_timing_cv,
            // CV of busy-loop wall-time is machine/load-dependent, compared by
            // outcome class so a 4.36-vs-3.00 (both Pass) is agreement, not a tell.
            determinism: Determinism::Stochastic,
        },
        Probe {
            name: "redteam(sear): standard web-platform APIs all present",
            js: MISSING_APIS_JS,
            severity: Severity::High,
            classifier: classify_missing_apis,
            determinism: Determinism::Deterministic,
        },
        Probe {
            name: "redteam(sear): no automation-framework globals leak",
            js: AUTOMATION_GLOBALS_JS,
            severity: Severity::High,
            classifier: classify_automation_globals,
            determinism: Determinism::Deterministic,
        },
        Probe {
            name: "redteam(sear): typeof document.all === 'undefined' (V8/HTML quirk)",
            js: DOCUMENT_ALL_JS,
            severity: Severity::Medium,
            classifier: classify_document_all,
            determinism: Determinism::Deterministic,
        },
        Probe {
            name: "redteam(sear): performance.now provides a high-resolution timer",
            js: TIMER_RESOLUTION_JS,
            severity: Severity::Medium,
            classifier: classify_timer_resolution,
            // Smallest timer delta is entropy-driven; classify rather than value-diff.
            determinism: Determinism::Stochastic,
        },
        Probe {
            name: "redteam(sear): UA browser-family agrees with capability-API surface",
            js: FP_API_COHERENCE_JS,
            severity: Severity::High,
            classifier: classify_fp_api_coherence,
            determinism: Determinism::Deterministic,
        },
        Probe {
            name: "redteam(sear): UA browser-family agrees with Error subsystem (stack shape)",
            js: ERROR_ENGINE_COHERENCE_JS,
            severity: Severity::High,
            classifier: classify_error_engine_coherence,
            determinism: Determinism::Deterministic,
        },
        Probe {
            name: "redteam: HTMLIFrameElement.contentWindow getter is native code",
            js: IFRAME_CONTENTWINDOW_JS,
            severity: Severity::High,
            classifier: classify_must_be_native_code,
            determinism: Determinism::Deterministic,
        },
        Probe {
            name: "redteam: Permissions.prototype.query is native code",
            js: PERMISSIONS_QUERY_JS,
            severity: Severity::High,
            classifier: classify_must_be_native_code,
            determinism: Determinism::Deterministic,
        },
    ]
}

fn classify_timing_cv(v: &serde_json::Value) -> ProbeOutcome {
    use crate::sampling::{CV_DRIFT_FLOOR, HUMAN_TIMING_CV_FLOOR};
    match v.as_f64() {
        Some(cv) if cv < 0.0 => {
            ProbeOutcome::Critical("busy loop took 0 ms, timer is instrumented/instant".into())
        }
        Some(cv) if cv >= HUMAN_TIMING_CV_FLOOR => ProbeOutcome::Pass,
        Some(cv) if cv >= CV_DRIFT_FLOOR => {
            ProbeOutcome::Drift(format!("timing CV {cv:.4} is low, borderline uniform"))
        }
        Some(cv) => ProbeOutcome::Critical(format!(
            "timing CV {cv:.4} < {CV_DRIFT_FLOOR}, near-uniform timer, sandbox tell"
        )),
        None => ProbeOutcome::ProbeError("timing-CV probe did not return a number".into()),
    }
}

fn classify_missing_apis(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_u64() {
        Some(0) => ProbeOutcome::Pass,
        Some(n) if n < 4 => ProbeOutcome::Drift(format!("{n} standard web API(s) missing")),
        Some(n) => ProbeOutcome::Critical(format!(
            "{n} standard web APIs missing, sandbox-grade surface"
        )),
        None => ProbeOutcome::ProbeError("missing-API probe did not return an integer".into()),
    }
}

fn classify_automation_globals(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_array() {
        Some(a) if a.is_empty() => ProbeOutcome::Pass,
        Some(a) => {
            let names: Vec<String> = a
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
            ProbeOutcome::Critical(format!("automation globals leaked: {}", names.join(", ")))
        }
        None => ProbeOutcome::ProbeError("automation-globals probe did not return an array".into()),
    }
}

fn classify_document_all(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_str() {
        Some("undefined") => ProbeOutcome::Pass,
        Some(other) => ProbeOutcome::Critical(format!(
            "typeof document.all is '{other}', not 'undefined', non-Chrome / shimmed"
        )),
        None => ProbeOutcome::ProbeError("document.all probe did not return a string".into()),
    }
}

fn classify_timer_resolution(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_f64() {
        Some(r) if r < 0.0 => {
            ProbeOutcome::Critical("performance.now() is missing, sandbox tell".into())
        }
        Some(0.0) => ProbeOutcome::Drift(
            "performance.now() never advanced even under sustained work, a frozen / \
             virtualized timer (privacy clamping alone advances within a few hundred \
             iterations)"
                .into(),
        ),
        Some(_) => ProbeOutcome::Pass,
        None => ProbeOutcome::ProbeError("timer-resolution probe did not return a number".into()),
    }
}

/// Chromium-only capability surfaces (a real Gecko build exposes none of these).
///
/// `serial` is deliberately ABSENT from this set: measured against a vanilla,
/// non-automated Firefox 151 (`navigator.webdriver === false`) on a secure
/// origin, `navigator.serial` is a live `object`: Firefox ships Web Serial in
/// a secure context. Treating it as Blink-only false-flagged a genuine current
/// Firefox as a bot (the stale-model tell that surfaced on the live probe gate).
/// `usb`/`hid`/`bluetooth`/`getBattery` remain Gecko-absent (measured undefined).
const CHROMIUM_ONLY_CAPABILITY_APIS: &[&str] = &["usb", "hid", "bluetooth", "getBattery"];

fn classify_fp_api_coherence(v: &serde_json::Value) -> ProbeOutcome {
    let Some(ua) = v.get("ua").and_then(|x| x.as_str()) else {
        return ProbeOutcome::ProbeError("api-coherence probe returned no ua".into());
    };
    let present = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    let is_firefox = ua.contains("Firefox") || ua.contains("Gecko/");
    let is_chrome = ua.contains("Chrome") || ua.contains("Chromium");

    if is_firefox {
        let leaked: Vec<&str> = CHROMIUM_ONLY_CAPABILITY_APIS
            .iter()
            .copied()
            .filter(|k| present(k))
            .collect();
        if !leaked.is_empty() {
            return ProbeOutcome::Critical(format!(
                "Firefox UA but Chromium-only API(s) present: navigator.{}, capability set says Blink",
                leaked.join(", navigator.")
            ));
        }
        if !present("mediaDevices") {
            return ProbeOutcome::Drift("Firefox persona missing navigator.mediaDevices".into());
        }
        return ProbeOutcome::Pass;
    }
    if is_chrome {
        let n = CHROMIUM_ONLY_CAPABILITY_APIS
            .iter()
            .filter(|k| present(k))
            .count();
        if n == 0 {
            return ProbeOutcome::Drift(
                "Chrome UA but no Blink capability APIs present, stripped/headless tell".into(),
            );
        }
        return ProbeOutcome::Pass;
    }
    ProbeOutcome::Pass
}

/// V8/Chromium-only members of the `Error` constructor, the error-subsystem
/// analog of the Blink capability set.
///
/// `captureStackTrace` is deliberately ABSENT: measured against a vanilla,
/// non-automated Firefox 151, `Error.captureStackTrace` is a live `function`
/// Firefox shipped it for V8 compatibility in v122 (Jan 2024). It is no longer a
/// V8 discriminator, and flagging it false-failed a genuine current Firefox.
/// `stackTraceLimit` and `prepareStackTrace` stay Gecko-absent (measured
/// undefined on FF-151), and the V8-vs-Gecko stack SHAPE check below remains the
/// primary discriminator.
const V8_ONLY_ERROR_MEMBERS: &[&str] = &["stackTraceLimit", "prepareStackTrace"];

fn classify_error_engine_coherence(v: &serde_json::Value) -> ProbeOutcome {
    let Some(ua) = v.get("ua").and_then(|x| x.as_str()) else {
        return ProbeOutcome::ProbeError("error-coherence probe returned no ua".into());
    };
    let present = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    let shape = v
        .get("stackShape")
        .and_then(|x| x.as_str())
        .unwrap_or("none");
    let is_firefox = ua.contains("Firefox") || ua.contains("Gecko/");
    let is_chrome = ua.contains("Chrome") || ua.contains("Chromium");

    if is_firefox {
        let leaked: Vec<&str> = V8_ONLY_ERROR_MEMBERS
            .iter()
            .copied()
            .filter(|k| present(k))
            .collect();
        if !leaked.is_empty() {
            return ProbeOutcome::Critical(format!(
                "Firefox UA but V8-only Error.{} present, error subsystem says V8/Chromium",
                leaked.join(", Error.")
            ));
        }
        if shape == "v8" {
            return ProbeOutcome::Critical(
                "Firefox UA but Chrome-style ('at') stack frames, running on V8".into(),
            );
        }
        // 'gecko' (the real Firefox shape) and 'none' (no stack captured) both
        // pass (a genuine Gecko build never renders V8-style frames).
        return ProbeOutcome::Pass;
    }
    if is_chrome {
        if !present("captureStackTrace") {
            return ProbeOutcome::Drift(
                "Chrome UA but Error.captureStackTrace absent, non-V8/shimmed tell".into(),
            );
        }
        if shape == "gecko" {
            return ProbeOutcome::Drift(
                "Chrome UA but Gecko-style ('@') stack frames, engine mismatch".into(),
            );
        }
        return ProbeOutcome::Pass;
    }
    ProbeOutcome::Pass
}

#[cfg(test)]
#[path = "redteam/tests.rs"]
mod tests;
