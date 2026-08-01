//! Web Worker / Worklet realm probes (G200 / G201).
//!
//! (No ServiceWorker realm probe: a SW cannot be registered from a blob/data
//! script URL, so a generic probe cannot enter that realm, see the NOTE below.)
//!
//! Real anti-bot scripts increasingly probe realms beyond `window`: Web Workers,
//! Service Workers, and worklets expose the same engine identity, so a spoof
//! that only patches `window` leaves an obvious cross-realm coherence tell.
//! These probes run a small script inside each realm and compare the reported
//! `navigator` identity values against the `window` values.

use super::{Determinism, Probe, ProbeOutcome, Severity};

/// Snapshot of navigator identity fields taken inside a realm.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
struct NavigatorSnapshot {
    #[serde(rename = "ua")]
    user_agent: String,
    #[serde(rename = "platform")]
    platform: String,
    #[serde(rename = "language")]
    language: String,
    #[serde(rename = "hc")]
    hardware_concurrency: i64,
    #[serde(rename = "ps")]
    product_sub: Option<String>,
    #[serde(rename = "wd")]
    webdriver: Option<bool>,
}

/// Result returned by the worker-realm probe: window snapshot + realm snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
struct RealmResult {
    window: NavigatorSnapshot,
    realm: NavigatorSnapshot,
}

/// JS that starts a dedicated Worker from a Blob, collects a `navigator`
/// snapshot inside the worker, and returns it alongside the window snapshot.
const WORKER_REALM_JS: &str = r#"(function(){
  function snap() {
    var n = navigator;
    return {
      ua: n.userAgent || '',
      platform: n.platform || '',
      language: n.language || '',
      hc: n.hardwareConcurrency || 0,
      ps: n.productSub || null,
      wd: typeof n.webdriver === 'boolean' ? n.webdriver : null
    };
  }
  return new Promise(function(resolve, reject){
    var script = "self.onmessage = function(e){ self.postMessage({" +
      "ua: navigator.userAgent || ''," +
      "platform: navigator.platform || ''," +
      "language: navigator.language || ''," +
      "hc: navigator.hardwareConcurrency || 0," +
      "ps: navigator.productSub || null," +
      "wd: typeof navigator.webdriver === 'boolean' ? navigator.webdriver : null" +
      "}); };";
    var blob = new Blob([script], {type: 'application/javascript'});
    var url = URL.createObjectURL(blob);
    var w = new Worker(url);
    w.onmessage = function(e){
      resolve({window: snap(), realm: e.data});
      w.terminate();
      URL.revokeObjectURL(url);
    };
    w.onerror = function(e){
      reject(String(e.message || 'worker error'));
    };
    w.postMessage('go');
  });
})()"#;

// NOTE: there is intentionally NO ServiceWorker realm probe. A ServiceWorker can
// only be registered from a same-origin HTTP(S) script URL: `blob:`/`data:`
// script URLs are rejected by the platform ("Invalid scope trying to resolve ./
// with base URL blob:…", confirmed live), unlike a dedicated Worker which DOES
// accept a blob URL. A generic probe cannot serve a SW script on an arbitrary
// origin, so the realm could never be entered; the old blob-based probe threw on
// every secure origin and (because the promise was never awaited) silently scored
// a clean Pass via its `null` branch, a Law-10 false pass. The Web Worker realm
// probe below covers the same window-vs-worker navigator coherence and actually
// runs, so ServiceWorker-realm coherence is dropped rather than faked.

/// JS that reports whether AudioWorklet and PaintWorklet globals are present.
///
/// The `audioWorklet` accessor lives on `BaseAudioContext.prototype` (inherited by
/// `AudioContext.prototype`), so its presence is read off the prototype chain with
/// `in`: NEVER by constructing an `AudioContext`. Instantiating one here would
/// (a) leak an unclosed audio context, (b) be an observable side effect inside the
/// very page we are trying to keep clean, and (c) THROW, aborting the whole probe
/// into a ProbeError, once the page hits the browser's per-document AudioContext
/// cap (~6 in Chrome) or under an autoplay/gesture policy. The prototype check has
/// none of those failure modes and computes the identical boolean.
const WORKLET_PRESENCE_JS: &str = r#"(function(){
  return {
    audioWorklet: typeof AudioWorklet === 'function' && !!(window.AudioContext && AudioContext.prototype && ('audioWorklet' in AudioContext.prototype)),
    paintWorklet: typeof CSS === 'object' && typeof CSS.paintWorklet === 'object'
  };
})()"#;

pub(super) fn realm_probes() -> Vec<Probe> {
    vec![
        Probe {
            name: "realm: Web Worker navigator matches window",
            js: WORKER_REALM_JS,
            severity: Severity::High,
            classifier: classify_worker_realm,
            determinism: Determinism::Deterministic,
        },
        Probe {
            name: "realm: AudioWorklet / PaintWorklet presence",
            js: WORKLET_PRESENCE_JS,
            severity: Severity::Low,
            classifier: classify_worklet_presence,
            determinism: Determinism::Deterministic,
        },
    ]
}

fn classify_worker_realm(v: &serde_json::Value) -> ProbeOutcome {
    let result = match serde_json::from_value::<RealmResult>(v.clone()) {
        Ok(r) => r,
        Err(e) => {
            return ProbeOutcome::ProbeError(format!("worker realm probe did not deserialize: {e}"))
        }
    };
    classify_realm_coherence(&result, "Web Worker")
}

fn classify_realm_coherence(result: &RealmResult, realm_name: &str) -> ProbeOutcome {
    let w = &result.window;
    let r = &result.realm;

    if r.webdriver == Some(true) {
        return ProbeOutcome::Critical(format!("{realm_name} navigator.webdriver === true"));
    }

    let mut mismatches: Vec<String> = Vec::new();
    if w.user_agent != r.user_agent {
        mismatches.push(format!("ua '{}' vs '{}'", r.user_agent, w.user_agent));
    }
    if w.platform != r.platform {
        mismatches.push(format!("platform '{}' vs '{}'", r.platform, w.platform));
    }
    if w.language != r.language {
        mismatches.push(format!("language '{}' vs '{}'", r.language, w.language));
    }
    if w.hardware_concurrency != r.hardware_concurrency {
        mismatches.push(format!(
            "hardwareConcurrency {} vs {}",
            r.hardware_concurrency, w.hardware_concurrency
        ));
    }
    // `productSub` is compared ONLY when the worker realm actually exposes it.
    // Firefox's WorkerNavigator does NOT implement productSub, so a real Firefox
    // reports window `"20100101"` vs worker `null`: verified live on the BARE,
    // un-stealthed engine (tests/probe_live.rs), i.e. this difference exists with
    // no disguise at all. Flagging it would Drift every genuine Firefox. A true
    // cross-realm spoofing inconsistency (window and worker BOTH present but
    // different) is still caught; an absent worker value is a WorkerNavigator API
    // fact, not a coherence tell.
    if r.product_sub.is_some() && w.product_sub != r.product_sub {
        mismatches.push(format!(
            "productSub {:?} vs {:?}",
            r.product_sub, w.product_sub
        ));
    }

    if mismatches.is_empty() {
        ProbeOutcome::Pass
    } else {
        ProbeOutcome::Drift(format!(
            "{realm_name} navigator snapshot diverges from window: {}",
            mismatches.join(", ")
        ))
    }
}

/// Whether a captured worker-realm snapshot is INTERNALLY coherent, the worker's
/// `navigator` identity matches the window's (no `webdriver===true`, no
/// ua/platform/language/hardwareConcurrency mismatch).
///
/// The reynard differential gate uses this to separate a BENIGN persona-vs-host VALUE
/// difference (e.g. `hardwareConcurrency` 8 vs 32, where each browser's worker still
/// matches its own window) from a REAL engine tell (the worker leaking a different
/// identity than the window). A cross-browser value divergence on this probe is expected
/// whenever the persona differs from the raw host; the engine claim it actually verifies
/// is intra-browser realm coherence, which is what this checks.
///
/// `serialized` is the probe's captured value string (the `{"window":…,"realm":…}` JSON).
/// FAIL-CLOSED: an un-parseable or incoherent snapshot returns `false`, so a caller must
/// NOT excuse it (Law 10 (never silently wave through what cannot be proven coherent)).
#[must_use]
pub fn worker_realm_is_self_coherent(serialized: &str) -> bool {
    serde_json::from_str::<RealmResult>(serialized)
        .map(|r| {
            matches!(
                classify_realm_coherence(&r, "Web Worker"),
                ProbeOutcome::Pass
            )
        })
        .unwrap_or(false)
}

fn classify_worklet_presence(v: &serde_json::Value) -> ProbeOutcome {
    #[derive(serde::Deserialize)]
    struct Presence {
        #[serde(rename = "audioWorklet")]
        audio_worklet: bool,
        #[serde(rename = "paintWorklet")]
        paint_worklet: bool,
    }
    match serde_json::from_value::<Presence>(v.clone()) {
        Ok(p) if p.audio_worklet || p.paint_worklet => ProbeOutcome::Pass,
        Ok(_) => ProbeOutcome::Drift(
            "neither AudioWorklet nor PaintWorklet present, unusual for a modern browser".into(),
        ),
        Err(e) => {
            ProbeOutcome::ProbeError(format!("worklet presence probe did not deserialize: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snap(ua: &str) -> NavigatorSnapshot {
        NavigatorSnapshot {
            user_agent: ua.to_string(),
            platform: "Linux x86_64".to_string(),
            language: "en-US".to_string(),
            hardware_concurrency: 8,
            product_sub: Some("20100101".to_string()),
            webdriver: Some(false),
        }
    }

    #[test]
    fn coherent_worker_realm_passes() {
        let s = snap("Mozilla/5.0 Firefox/151.0");
        let v = json!({"window": s.clone(), "realm": s});
        assert_eq!(classify_worker_realm(&v), ProbeOutcome::Pass);
    }

    #[test]
    fn self_coherent_helper_matches_classifier_and_fails_closed() {
        // Coherent (worker == window) → true, regardless of the persona VALUE.
        let s = snap("Mozilla/5.0 Firefox/151.0");
        let coherent = serde_json::to_string(&json!({"window": s.clone(), "realm": s})).unwrap();
        assert!(worker_realm_is_self_coherent(&coherent));

        // Worker hardwareConcurrency leaks a different value than the window → false.
        let w = snap("Mozilla/5.0 Firefox/151.0");
        let mut leak = w.clone();
        leak.hardware_concurrency = 32;
        let incoherent = serde_json::to_string(&json!({"window": w, "realm": leak})).unwrap();
        assert!(!worker_realm_is_self_coherent(&incoherent));

        // Worker webdriver === true (a real tell) → false even if all else matches.
        let w2 = snap("Mozilla/5.0 Firefox/151.0");
        let mut wd = w2.clone();
        wd.webdriver = Some(true);
        let driven = serde_json::to_string(&json!({"window": w2, "realm": wd})).unwrap();
        assert!(!worker_realm_is_self_coherent(&driven));

        // Un-parseable / shapeless input → fail-closed false (never silently excuse).
        assert!(!worker_realm_is_self_coherent("not json"));
        assert!(!worker_realm_is_self_coherent("{}"));
    }

    #[test]
    fn worker_ua_mismatch_is_drift() {
        let w = snap("Mozilla/5.0 Firefox/151.0");
        let mut r = w.clone();
        r.user_agent = "Mozilla/5.0 Chrome/131.0".to_string();
        let v = json!({"window": w, "realm": r});
        match classify_worker_realm(&v) {
            ProbeOutcome::Drift(m) => assert!(m.contains("ua")),
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn worker_absent_productsub_is_not_a_drift_firefox_native() {
        // Firefox's WorkerNavigator does not expose productSub, so a real Firefox
        // reports window "20100101" vs worker null. Everything else matches. This
        // must PASS (it is the live BARE-engine behaviour, not a disguise tell).
        let w = snap("Mozilla/5.0 Firefox/151.0");
        let mut r = w.clone();
        r.product_sub = None;
        let v = json!({"window": w, "realm": r});
        assert_eq!(
            classify_worker_realm(&v),
            ProbeOutcome::Pass,
            "an absent worker productSub is a WorkerNavigator API fact, not a coherence tell"
        );
    }

    #[test]
    fn worker_present_but_different_productsub_is_drift() {
        // When BOTH realms expose productSub and they disagree, that IS a real
        // cross-realm spoofing inconsistency and must still Drift.
        let w = snap("Mozilla/5.0 Firefox/151.0");
        let mut r = w.clone();
        r.product_sub = Some("20030107".to_string());
        let v = json!({"window": w, "realm": r});
        match classify_worker_realm(&v) {
            ProbeOutcome::Drift(m) => assert!(m.contains("productSub")),
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn worker_hardware_concurrency_leak_is_drift() {
        // The confirmed real leak: the main-thread hardwareConcurrency spoof does
        // not reach the Worker realm on the stock-BiDi JS-preload path, so window
        // reports the persona value while the worker reports the real core count.
        let w = snap("Mozilla/5.0 Firefox/151.0"); // window hc = 8 (spoofed)
        let mut r = w.clone();
        r.hardware_concurrency = 32; // worker hc = 32 (real machine)
        let v = json!({"window": w, "realm": r});
        match classify_worker_realm(&v) {
            ProbeOutcome::Drift(m) => assert!(m.contains("hardwareConcurrency")),
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn worker_webdriver_true_is_critical() {
        let w = snap("Mozilla/5.0 Firefox/151.0");
        let mut r = w.clone();
        r.webdriver = Some(true);
        let v = json!({"window": w, "realm": r});
        match classify_worker_realm(&v) {
            ProbeOutcome::Critical(m) => assert!(m.contains("webdriver")),
            other => panic!("expected Critical, got {other:?}"),
        }
    }

    #[test]
    fn worklet_presence_passes_when_any_present() {
        let v = json!({"audioWorklet": true, "paintWorklet": false});
        assert_eq!(classify_worklet_presence(&v), ProbeOutcome::Pass);
    }

    #[test]
    fn worklet_absence_is_drift() {
        let v = json!({"audioWorklet": false, "paintWorklet": false});
        match classify_worklet_presence(&v) {
            ProbeOutcome::Drift(m) => {
                assert!(m.contains("AudioWorklet") || m.contains("PaintWorklet"))
            }
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn realm_probe_list_has_worker_and_worklet_probes() {
        let probes = realm_probes();
        // Web Worker realm + Worklet presence. NO ServiceWorker realm probe: a SW
        // cannot be registered from a blob/data script URL, so that realm is
        // unreachable by a generic probe (see the NOTE at the module's SW section).
        assert_eq!(probes.len(), 2);
        let names: Vec<&str> = probes.iter().map(|p| p.name).collect();
        assert!(names.contains(&"realm: Web Worker navigator matches window"));
        assert!(names.contains(&"realm: AudioWorklet / PaintWorklet presence"));
        assert!(
            !names.iter().any(|n| n.contains("ServiceWorker")),
            "ServiceWorker realm probe must stay removed, it can never run (blob SW invalid)"
        );
    }
}
