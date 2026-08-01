//! Lie-detector probe set (G193 / G194).
//!
//! CreepJS-class fingerprinters do not just read values; they look for the
//! *inconsistencies* that JS spoofing leaves behind. A common evasion pattern
//! is `Object.defineProperty(navigator, 'webdriver', {value: false})`, which
//! makes `navigator.webdriver` an OWN data property of the instance instead of
//! an inherited getter on `Navigator.prototype`. Another is replacing a native
//! getter with a wrapper whose `Function.prototype.toString` no longer contains
//! `[native code]`. These probes surface those tells.
//!
//! The probe returns a JSON array of lie names. The target is **zero lies**:
//! a real, un-spoofed browser produces an empty array; a spoofed/disguised page
//! produces one or more entries. The classifier is intentionally strict but
//! not hysterical: 1–2 lies is a `Drift`, 3+ is `Critical`.

use super::{Determinism, Probe, ProbeOutcome, Severity};

/// JavaScript that collects descriptor / toString inconsistencies commonly
/// flagged by CreepJS-style lie detectors.
const LIE_DETECTOR_JS: &str = r#"(function(){
  var lies = [];
  var hasOwn = Object.prototype.hasOwnProperty;
  function isNative(fn) {
    try { return typeof fn === 'function' && /\[native code\]/.test(Function.prototype.toString.call(fn)); } catch(e) { return false; }
  }
  // navigator.webdriver should be an inherited getter on Navigator.prototype,
  // never an own data property on the instance.
  try {
    var wdDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
    if (hasOwn.call(navigator, 'webdriver')) lies.push('navigator.webdriver is own property');
    if (!wdDesc || typeof wdDesc.get !== 'function' || !isNative(wdDesc.get)) lies.push('navigator.webdriver getter is not native');
  } catch(e) { lies.push('navigator.webdriver descriptor unreadable'); }
  // navigator.plugins / mimeTypes should be inherited PluginArray/MimeTypeArray,
  // not own data properties, and should toString correctly.
  try {
    if (hasOwn.call(navigator, 'plugins')) lies.push('navigator.plugins is own property');
    var plugins = navigator.plugins;
    if (plugins && Object.prototype.toString.call(plugins) !== '[object PluginArray]') lies.push('navigator.plugins toString mismatch');
  } catch(e) { lies.push('navigator.plugins unreadable'); }
  try {
    if (hasOwn.call(navigator, 'mimeTypes')) lies.push('navigator.mimeTypes is own property');
    var mimes = navigator.mimeTypes;
    if (mimes && Object.prototype.toString.call(mimes) !== '[object MimeTypeArray]') lies.push('navigator.mimeTypes toString mismatch');
  } catch(e) { lies.push('navigator.mimeTypes unreadable'); }
  // window.chrome on a real Firefox is absent; on a real Chrome it is an inherited
  // accessor or native object, not an own data property shoved onto window.
  try {
    if ('chrome' in window && hasOwn.call(window, 'chrome')) lies.push('window.chrome is own property');
  } catch(e) { lies.push('window.chrome check failed'); }
  // Function.prototype.toString should return native code for untouched builtins.
  try {
    if (!isNative(navigator.plugins && navigator.plugins.item)) lies.push('navigator.plugins.item is not native');
  } catch(e) { lies.push('navigator.plugins.item unreadable'); }
  return lies;
})()"#;

/// The lie-detector probe set. A single probe returns the list of detected lies.
pub(super) fn lie_detector_probes() -> Vec<Probe> {
    vec![Probe {
        name: "lie-detector: descriptor / toString inconsistencies",
        js: LIE_DETECTOR_JS,
        severity: Severity::High,
        classifier: classify_lie_count,
        determinism: Determinism::Deterministic,
    }]
}

/// Classify the lie-detector result.
///
/// * empty array ⇒ `Pass` (0 lies target).
/// * 1–2 lie names ⇒ `Drift` (suspicious but could be a benign extension).
/// * 3+ lie names ⇒ `Critical` (strong spoofing signature).
fn classify_lie_count(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_array() {
        Some(arr) if arr.is_empty() => ProbeOutcome::Pass,
        Some(arr) => {
            let lies: Vec<String> = arr
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
            let count_phrase = if lies.len() == 1 {
                "1 lie".to_string()
            } else {
                format!("{} lies", lies.len())
            };
            let msg = format!("lie detector found {count_phrase}: {}", lies.join(", "));
            if lies.len() >= 3 {
                ProbeOutcome::Critical(msg)
            } else {
                ProbeOutcome::Drift(msg)
            }
        }
        None => ProbeOutcome::ProbeError("lie-detector probe did not return an array".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_lies_passes() {
        assert_eq!(
            classify_lie_count(&serde_json::json!([])),
            ProbeOutcome::Pass
        );
    }

    #[test]
    fn one_lie_is_drift() {
        match classify_lie_count(&serde_json::json!(["navigator.webdriver is own property"])) {
            ProbeOutcome::Drift(msg) => assert!(msg.contains("1 lie")),
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn two_lies_are_drift() {
        match classify_lie_count(&serde_json::json!(["a", "b"])) {
            ProbeOutcome::Drift(msg) => assert!(msg.contains("2 lies")),
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn three_lies_are_critical() {
        match classify_lie_count(&serde_json::json!(["a", "b", "c"])) {
            ProbeOutcome::Critical(msg) => assert!(msg.contains("3 lies")),
            other => panic!("expected Critical, got {other:?}"),
        }
    }

    #[test]
    fn non_array_is_probe_error() {
        match classify_lie_count(&serde_json::json!("not an array")) {
            ProbeOutcome::ProbeError(_) => {}
            other => panic!("expected ProbeError, got {other:?}"),
        }
    }

    #[test]
    fn probe_list_is_non_empty() {
        let probes = lie_detector_probes();
        assert!(!probes.is_empty());
        assert_eq!(
            probes[0].name,
            "lie-detector: descriptor / toString inconsistencies"
        );
    }
}
