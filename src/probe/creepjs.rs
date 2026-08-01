//! CreepJS-style trust-score probe (G192).
//!
//! CreepJS computes a trust score from a battery of integrity checks: WebDriver
//! presence, plugin MIME richness, WebGL renderer, timezone resolution,
//! automation globals, error-stack markers, and so on. This probe mirrors that
//! scoring model so guise's oracle can expose a single, detector-meaningful
//! surface instead of requiring operators to mentally aggregate dozens of
//! individual probe outcomes.
//!
//! The score is computed entirely in the page so it reflects the live browser
//! state. It is calibrated to penalize the same signals CreepJS weights:
//! hard automation tells cost the most, missing entropy/richness costs less,
//! and a clean real browser should land near 100.

use super::{Probe, ProbeOutcome, Severity};

/// CreepJS-style trust-score probe. Returns an integer 0-100.
pub(super) fn creepjs_probes() -> Vec<Probe> {
    vec![super::catalogue::probe(
        "creepjs.trust_score",
        CREEPS_SCORE_JS,
        Severity::High,
        classify_creepjs_trust_score,
    )]
}

/// Penalty table (mirrors CreepJS weighting):
///   * webdriver === true              -45
///   * navigator.plugins.length == 0   -20
///   * navigator.mimeTypes.length == 0 -10
///   * navigator.languages missing     -10
///   * WebGL SwiftShader               -25
///   * Notification.permission denied  -10
///   * unstable canvas (per-read rand) -15
///   * unstable audio  (per-read rand) -10
///   * voices < 4                      -10
///   * empty IANA timezone             -20
///   * error stack automation markers  -15 each
///   * automation globals present      -15 each
const CREEPS_SCORE_JS: &str = r#"
(() => {
    let score = 100;
    const penalize = (cond, amount) => { if (cond) score -= amount; };

    // Hard automation tell.
    penalize(navigator.webdriver === true, 45);

    // Plugin / MIME richness (CreepJS treats empty PluginArray as suspicious).
    penalize(!navigator.plugins || navigator.plugins.length === 0, 20);
    penalize(!navigator.mimeTypes || navigator.mimeTypes.length === 0, 10);

    // Language entropy.
    penalize(!navigator.languages || navigator.languages.length === 0, 10);

    // WebGL renderer (SwiftShader is the classic software/headless tell).
    try {
        const c = document.createElement('canvas').getContext('webgl');
        if (c) {
            const ext = c.getExtension('WEBGL_debug_renderer_info');
            if (ext) {
                const vendor = c.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '';
                const renderer = c.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
                penalize(/swiftshader/i.test(vendor + renderer), 25);
            }
        }
    } catch (_) {}

    // Notification permission.
    try { penalize(Notification.permission === 'denied', 10); } catch (_) {}

    // Unstable canvas/audio (per-read randomization is itself a tell).
    try {
        const c = document.createElement('canvas');
        c.width = c.height = 50;
        const ctx = c.getContext('2d');
        ctx.fillStyle = 'red';
        ctx.fillRect(0, 0, 50, 50);
        const a = ctx.getImageData(0, 0, 50, 50).data;
        const b = ctx.getImageData(0, 0, 50, 50).data;
        let diff = 0;
        // Compare the RGB channels, the ones a canvas farble perturbs. The old
        // loop started at i=3 stepping by 4, i.e. it inspected ONLY the alpha
        // channel, which guise (and every naive farble) leaves untouched and which
        // a solid fill holds constant, so the documented "unstable canvas
        // (per-read rand)" penalty could never fire for the RGB per-read tell it
        // exists to catch. Mirror the standalone session-stability probe: compare
        // R/G/B (a[i],a[i+1],a[i+2]) and exclude the deliberately-untouched alpha.
        for (let i = 0; i < a.length; i += 4) { if (a[i] !== b[i] || a[i+1] !== b[i+1] || a[i+2] !== b[i+2]) diff++; }
        penalize(diff > 0, 15);
    } catch (_) {}

    try {
        const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (Ctx) {
            const ctx = new Ctx(1, 100, 44100);
            const buf = ctx.createBuffer(1, 100, 44100);
            const a = Array.from(buf.getChannelData(0));
            const b = Array.from(buf.getChannelData(0));
            penalize(JSON.stringify(a) !== JSON.stringify(b), 10);
        }
    } catch (_) {}

    // Voice list richness.
    try {
        const voices = window.speechSynthesis ? window.speechSynthesis.getVoices() : [];
        penalize(voices.length < 4, 10);
    } catch (_) {}

    // Timezone resolution.
    try {
        const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
        penalize(tz === '', 20);
    } catch (_) {}

    // Error-stack automation markers.
    try {
        let stack = '';
        try { throw new Error('probe'); } catch (e) { stack = e.stack || ''; }
        penalize(/_puppeteer_evaluation_script_/.test(stack), 15);
        penalize(/_cdpEvaluate/.test(stack), 15);
    } catch (_) {}

    // Automation globals.
    const globals = ['__nightmare', '_phantom', 'callPhantom', '_selenium', 'cdc_adoQpoasnfa76pfcZLmcfl_', 'cdc_adoQpoasnfa76pfcZLmcfl_PyValidator_'];
    for (const g of globals) {
        try { penalize(typeof window[g] !== 'undefined', 15); } catch (_) {}
    }

    return Math.max(0, score);
})()
"#;

/// Classify the CreepJS-style trust score.
///
/// CreepJS itself renders scores near 100 for genuine browsers and < 50 for
/// heavily automated ones. We mirror that threshold: ≥ 80 is a pass, 40-79 is a
/// drift (some suspicion), < 40 is critical (likely automation).
pub(super) fn classify_creepjs_trust_score(v: &serde_json::Value) -> ProbeOutcome {
    match v.as_i64().or_else(|| v.as_u64().map(|n| n as i64)) {
        Some(n) if n >= 80 => ProbeOutcome::Pass,
        Some(n) if n >= 40 => {
            ProbeOutcome::Drift(format!("trust score {n} is below high-trust threshold"))
        }
        Some(n) => ProbeOutcome::Critical(format!("trust score {n} indicates heavy automation")),
        None => ProbeOutcome::Drift(format!("trust score not a number: {v}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_trust_score_passes() {
        assert_eq!(
            classify_creepjs_trust_score(&serde_json::json!(100)),
            ProbeOutcome::Pass
        );
        assert_eq!(
            classify_creepjs_trust_score(&serde_json::json!(80)),
            ProbeOutcome::Pass
        );
    }

    #[test]
    fn medium_trust_score_drifts() {
        match classify_creepjs_trust_score(&serde_json::json!(50)) {
            ProbeOutcome::Drift(m) => assert!(m.contains("50")),
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn low_trust_score_is_critical() {
        match classify_creepjs_trust_score(&serde_json::json!(20)) {
            ProbeOutcome::Critical(m) => assert!(m.contains("20")),
            other => panic!("expected Critical, got {other:?}"),
        }
    }

    #[test]
    fn non_numeric_score_drifts() {
        match classify_creepjs_trust_score(&serde_json::json!("nope")) {
            ProbeOutcome::Drift(_) => {}
            other => panic!("expected Drift, got {other:?}"),
        }
    }

    #[test]
    fn probe_is_in_catalogue_for_both_families() {
        use crate::fingerprint::UserAgentBrowser;
        for browser in [UserAgentBrowser::Chrome, UserAgentBrowser::Firefox] {
            let names: std::collections::HashSet<&str> = super::super::probes_for(browser)
                .iter()
                .map(|p| p.name)
                .collect();
            assert!(
                names.contains("creepjs.trust_score"),
                "creepjs.trust_score must be in the {browser:?} catalogue"
            );
        }
    }
}
