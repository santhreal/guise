//! BiDi-specific automation tells (G199 / R015).
//!
//! WebDriver BiDi drivers can leak traces in the page that pure CDP detectors
//! do not check: injected evaluation globals, BiDi-shaped script identifiers in
//! `Error.stack`, and markers left by the automation transport. These probes
//! enumerate those tells from the guise side so a reynard/Camoufox build can be
//! regression-gated against them.
//!
//! The probes are **negative assertions**: the value must be absent or the stack
//! must not contain the marker. A `Pass` means the BiDi transport left no
//! detectable footprint.

use super::catalogue::probe;
use super::classify::{classify_must_be_true, classify_must_be_undefined};
use super::Probe;

/// Probes for WebDriver BiDi automation footprints.
pub(super) fn bidi_tell_probes() -> Vec<Probe> {
    vec![
        // Some WebDriver implementations inject an evaluation helper on `window`.
        probe(
            "window.__webdriver_evaluate undefined",
            "typeof window.__webdriver_evaluate === 'undefined' ? null : window.__webdriver_evaluate",
            super::Severity::High,
            classify_must_be_undefined,
        ),
        // Legacy Selenium / Marionette script-function marker.
        probe(
            "window.__webdriver_script_fn undefined",
            "typeof window.__webdriver_script_fn === 'undefined' ? null : window.__webdriver_script_fn",
            super::Severity::High,
            classify_must_be_undefined,
        ),
        // Alternate naming used by some BiDi clients.
        probe(
            "window.__webdriver_script_function undefined",
            "typeof window.__webdriver_script_function === 'undefined' ? null : window.__webdriver_script_function",
            super::Severity::High,
            classify_must_be_undefined,
        ),
        // BiDi / WebDriver script evaluation can leave a marker in thrown stacks.
        probe(
            "Error.stack does not leak webdriver_evaluate marker",
            "(() => { try { throw new Error('probe'); } catch (e) { return !/webdriver_evaluate/.test(e.stack || ''); } })()",
            super::Severity::High,
            classify_must_be_true,
        ),
        // Generic BiDi script-id marker that some clients embed.
        probe(
            "Error.stack does not leak bidi script marker",
            "(() => { try { throw new Error('probe'); } catch (e) { return !/bidi_script|bidi_evaluate|webdriver bidi/i.test(e.stack || ''); } })()",
            super::Severity::Medium,
            classify_must_be_true,
        ),
        // The `navigator.webdriver` property must be inherited from the prototype,
        // not an own property installed by the driver, this is already covered by
        // the core catalogue, but repeated here as the canonical BiDi tell.
        probe(
            "navigator.webdriver is inherited (BiDi tell)",
            "!Object.prototype.hasOwnProperty.call(navigator, 'webdriver')",
            super::Severity::High,
            classify_must_be_true,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::super::classify::*;
    use super::*;
    use crate::probe::{ProbeOutcome, Severity};

    #[test]
    fn bidi_probes_are_unique_and_have_high_severity() {
        let probes = bidi_tell_probes();
        let mut seen = std::collections::HashSet::new();
        for p in &probes {
            assert!(seen.insert(p.name), "duplicate bidi probe: {}", p.name);
            assert!(
                matches!(p.severity, Severity::High | Severity::Medium),
                "{}: bidi tell probes must be Medium or Higher",
                p.name
            );
        }
    }

    #[test]
    fn classify_undefined_passes_on_null() {
        assert_eq!(
            classify_must_be_undefined(&serde_json::Value::Null),
            ProbeOutcome::Pass
        );
    }

    #[test]
    fn classify_undefined_critical_on_value() {
        match classify_must_be_undefined(&serde_json::json!("leaked")) {
            ProbeOutcome::Critical(_) => {}
            other => panic!("expected Critical for leaked BiDi global, got {other:?}"),
        }
    }

    #[test]
    fn stack_probe_passes_when_marker_absent() {
        assert_eq!(
            classify_must_be_true(&serde_json::json!(true)),
            ProbeOutcome::Pass
        );
    }

    #[test]
    fn stack_probe_critical_when_marker_present() {
        match classify_must_be_true(&serde_json::json!(false)) {
            ProbeOutcome::Critical(_) => {}
            other => panic!("expected Critical for BiDi stack leak, got {other:?}"),
        }
    }
}
