//! Offline oracle fixture (deterministic CI without a live browser (G190)).
//!
//! A fixture is a pair of [`Capture`](super::oracle::Capture)s: one from a
//! baseline browser and one from a candidate/disguise. The oracle's
//! [`diff_captures`](super::oracle::diff_captures) function diffs them
//! byte-for-byte, producing the same `DifferentialReport` and `Scorecard` a live
//! run would (but without launching browsers).
//!
//! The fixture shipped here is **synthetic**: it models a plausible stock
//! Firefox vs a JS-disguise divergence set so the oracle rendering, scorecard
//! generation, and prioritization are regression-locked in CI. It can be
//! replaced by a real captured fixture produced by
//! [`capture_page`](super::oracle::capture_page) whenever an operator runs the
//! live gate.

use super::{Capture, CapturedSurface, Severity};

/// A synthetic but representative offline fixture: stock Firefox vs a JS
/// disguise that overrides a few identity surfaces.
pub fn synthetic_firefox_fixture() -> (Capture, Capture) {
    let stock = stock_firefox_capture();
    let mut disguise = stock.clone();
    disguise.label = "js-disguise".to_string();

    // The disguise overrides hardwareConcurrency from 8 → 4 (persona-intended).
    set_value(
        &mut disguise,
        "navigator.hardwareConcurrency in [2, 16]",
        "4",
    );
    // The disguise overrides screen.width from 1920 → 1366 (persona-intended).
    set_value(&mut disguise, "screen.width plausible", "1366");
    // The disguise accidentally leaks webdriver and window.chrome (engine-level tells).
    set_value(&mut disguise, "navigator.webdriver", "true");
    set_value(&mut disguise, "window.chrome.runtime exists", "true");
    // The disguise's plugins.length differs from stock (engine-level tell).
    set_value(&mut disguise, "navigator.plugins.length > 0", "1");
    // The disguise varies canvas PER READ (the instability tell), value "true"
    // means "differs between two reads", which the classifier now flags as Drift
    // (a correct, session-stable farble would read "false"). It diverges from the
    // stable stock capture, so it surfaces as a divergence.
    set_value(
        &mut disguise,
        "CanvasRenderingContext2D getImageData session-stable (no per-read tell)",
        "true",
    );

    (stock, disguise)
}

fn set_value(capture: &mut Capture, name: &str, value: &str) {
    if let Some(s) = capture.surfaces.iter_mut().find(|s| s.name == name) {
        s.value = Ok(value.to_string());
    }
}

fn s(name: &'static str, severity: Severity, value: &str) -> CapturedSurface {
    CapturedSurface {
        name: name.to_string(),
        severity,
        value: Ok(value.to_string()),
    }
}

fn stock_firefox_capture() -> Capture {
    Capture {
        label: "stock-firefox".to_string(),
        surfaces: vec![
            s("navigator.webdriver", Severity::High, "false"),
            s(
                "navigator.webdriver is inherited, not an own property",
                Severity::High,
                "true",
            ),
            s("navigator.plugins.length > 0", Severity::High, "3"),
            s(
                "navigator.plugins is a real PluginArray",
                Severity::High,
                "true",
            ),
            s("navigator.mimeTypes.length > 0", Severity::Medium, "2"),
            s("navigator.languages.length > 0", Severity::High, "2"),
            s("navigator.language", Severity::Low, "en-US"),
            s("navigator.vendor non-empty", Severity::Medium, ""),
            s(
                "navigator.userAgent",
                Severity::High,
                "Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0",
            ),
            s("navigator.appVersion non-empty", Severity::Low, "5.0 (X11)"),
            s(
                "navigator.platform non-empty",
                Severity::Medium,
                "Linux x86_64",
            ),
            s("navigator.cookieEnabled true", Severity::Low, "true"),
            s("navigator.onLine true", Severity::Low, "true"),
            s("navigator.pdfViewerEnabled true", Severity::Low, "true"),
            s("navigator.product equals 'Gecko'", Severity::Low, "Gecko"),
            s(
                "navigator.productSub equals '20100101'",
                Severity::Low,
                "20100101",
            ),
            s(
                "navigator.appName equals 'Netscape'",
                Severity::Low,
                "Netscape",
            ),
            s(
                "navigator.appCodeName equals 'Mozilla'",
                Severity::Low,
                "Mozilla",
            ),
            s(
                "WebGL UNMASKED_VENDOR not SwiftShader",
                Severity::High,
                "NVIDIA",
            ),
            s(
                "WebGL UNMASKED_RENDERER not SwiftShader",
                Severity::High,
                "NVIDIA GeForce GTX 1660",
            ),
            s(
                "Notification.permission not 'denied'",
                Severity::Medium,
                "true",
            ),
            s("window.chrome.runtime exists", Severity::High, "false"),
            s(
                "window.chrome.app.RunningState exists",
                Severity::Medium,
                "false",
            ),
            s(
                "window.chrome.loadTimes returns object",
                Severity::Medium,
                "false",
            ),
            s(
                "window.chrome.csi returns object",
                Severity::Medium,
                "false",
            ),
            s(
                "CanvasRenderingContext2D getImageData session-stable (no per-read tell)",
                Severity::Medium,
                "false",
            ),
            s(
                "HTMLCanvasElement.toDataURL session-stable (no per-read tell)",
                Severity::Medium,
                "false",
            ),
            s(
                "AudioBuffer.getChannelData session-stable (no per-read tell)",
                Severity::Medium,
                "false",
            ),
            s("RTCPeerConnection exists", Severity::Medium, "true"),
            s(
                "navigator.hardwareConcurrency in [2, 16]",
                Severity::Low,
                "8",
            ),
            s("navigator.deviceMemory in [1, 64]", Severity::Low, "8"),
            s(
                "navigator.permissions.query exists",
                Severity::Medium,
                "true",
            ),
            s(
                "navigator.mediaDevices.enumerateDevices returns >=2",
                Severity::Medium,
                "2",
            ),
            s("navigator.serviceWorker exists", Severity::Medium, "true"),
            s(
                "speechSynthesis.getVoices returns >=16 voices",
                Severity::Medium,
                "20",
            ),
            s("window.visualViewport exists", Severity::Low, "true"),
            s("screen.colorDepth == 24", Severity::Low, "24"),
            s("screen.pixelDepth == 24", Severity::Low, "24"),
            s("screen.orientation.type exists", Severity::Low, "true"),
            s("screen.width plausible", Severity::Low, "1920"),
            s("screen.height plausible", Severity::Low, "1080"),
            s("window.outerWidth >= innerWidth", Severity::Medium, "true"),
            s("window.outerHeight >= 100", Severity::Medium, "true"),
            s("window.devicePixelRatio sensible", Severity::Low, "1"),
            s("performance.now precision floored", Severity::Low, "true"),
            s(
                "Intl.DateTimeFormat resolves an IANA time zone",
                Severity::High,
                "America/New_York",
            ),
            s(
                "Error.stack does not leak puppeteer marker",
                Severity::High,
                "true",
            ),
            s(
                "Error.stack does not leak cdpEvaluate marker",
                Severity::High,
                "true",
            ),
            s("window.__nightmare undefined", Severity::Medium, "null"),
            s("window._phantom undefined", Severity::Medium, "null"),
            s("window.callPhantom undefined", Severity::Medium, "null"),
            s("window._selenium undefined", Severity::Medium, "null"),
            s(
                "Chrome remote-debugging WS unreachable from page",
                Severity::Medium,
                "true",
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::super::oracle::diff_captures;
    use super::*;
    use crate::fingerprint::UserAgentBrowser;

    #[test]
    fn synthetic_fixture_has_expected_divergences() {
        let (stock, disguise) = synthetic_firefox_fixture();
        let report = diff_captures(&stock, &disguise);
        // The fixture intentionally diverges on these surfaces.
        let names: Vec<_> = report
            .divergences
            .iter()
            .map(|d| d.surface.as_str())
            .collect();
        assert!(names.contains(&"navigator.hardwareConcurrency in [2, 16]"));
        assert!(names.contains(&"screen.width plausible"));
        assert!(names.contains(&"window.chrome.runtime exists"));
        assert!(names.contains(&"navigator.plugins.length > 0"));
        assert!(names
            .contains(&"CanvasRenderingContext2D getImageData session-stable (no per-read tell)"));
    }

    #[test]
    fn fixture_scorecard_is_deterministic_and_prioritizes_critical() {
        let (stock, disguise) = synthetic_firefox_fixture();
        let report = diff_captures(&stock, &disguise);
        let sc = crate::probe::scorecard_from_report(&report, UserAgentBrowser::Firefox);
        // webdriver is Critical (100 points) and an engine tell → top fix.
        let fixes: Vec<_> = sc.prioritized_fixes();
        assert!(!fixes.is_empty());
        assert_eq!(fixes[0].surface.surface_id, "navigator.webdriver");
        assert_eq!(fixes[0].benchmark_points, 100);
        // Serialization is stable (G218/G190).
        let json = serde_json::to_string(&sc).expect("serialize");
        let back = serde_json::from_str::<crate::probe::Scorecard>(&json).expect("deserialize");
        assert_eq!(back.lost_points, sc.lost_points);
        assert_eq!(back.entries, sc.entries);
    }

    #[test]
    fn stock_vs_stock_fixture_is_identical() {
        let (stock, _) = synthetic_firefox_fixture();
        let report = diff_captures(&stock, &stock);
        assert!(report.is_identical());
        assert!(crate::probe::scorecard_from_report(&report, UserAgentBrowser::Firefox).is_clean());
    }

    #[test]
    fn fixture_render_is_deterministic_across_runs() {
        let (stock, disguise) = synthetic_firefox_fixture();
        let r1 = crate::probe::render_differential(&diff_captures(&stock, &disguise));
        let r2 = crate::probe::render_differential(&diff_captures(&stock, &disguise));
        assert_eq!(
            r1, r2,
            "fixture-based oracle rendering must be deterministic"
        );
    }
}
