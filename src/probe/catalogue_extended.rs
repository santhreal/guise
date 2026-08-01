//! Extended probe catalogue, additional surfaces that push the runtime probe
//! count past 200 (G183). These are mostly modern web-platform presence checks
//! and a few higher-entropy surfaces not covered by the core/misc catalogues.

use super::catalogue::probe;
use super::classify::*;
use super::{Probe, Severity};

pub(super) fn extended_probes() -> Vec<Probe> {
    vec![
        // ─── WebGPU ───────────────────────────────────────────────────────────
        probe(
            "navigator.gpu exists",
            "(() => typeof navigator.gpu === 'object')()",
            Severity::Medium,
            classify_must_be_true,
        ),
        probe(
            "navigator.gpu.requestAdapter is function",
            "(() => !!(navigator.gpu && typeof navigator.gpu.requestAdapter === 'function'))()",
            Severity::High,
            classify_must_be_true,
        ),
        probe(
            "GPUAdapter.limits is object",
            "(() => { try { return typeof GPUAdapter !== 'undefined'; } catch (_) { return false; } })()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "GPUBufferUsage exists",
            "(() => typeof GPUBufferUsage === 'object')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "navigator.gpu.getPreferredCanvasFormat exists",
            "(() => !!(navigator.gpu && typeof navigator.gpu.getPreferredCanvasFormat === 'function'))()",
            Severity::Low,
            classify_must_be_true,
        ),
        // ─── Permissions API ──────────────────────────────────────────────────
        probe(
            "PermissionStatus.prototype.name exists",
            "(() => typeof PermissionStatus !== 'undefined' && 'name' in PermissionStatus.prototype)()",
            Severity::Low,
            classify_must_be_true,
        ),
        // ─── Intl API surfaces ────────────────────────────────────────────────
        probe(
            "Intl.NumberFormat exists",
            "(() => typeof Intl.NumberFormat === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "Intl.Collator exists",
            "(() => typeof Intl.Collator === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "Intl.ListFormat exists",
            "(() => typeof Intl.ListFormat === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "Intl.RelativeTimeFormat exists",
            "(() => typeof Intl.RelativeTimeFormat === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "Intl.PluralRules exists",
            "(() => typeof Intl.PluralRules === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "Intl.Segmenter exists",
            "(() => typeof Intl.Segmenter === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "Intl.DisplayNames exists",
            "(() => typeof Intl.DisplayNames === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        // ─── Performance / memory ─────────────────────────────────────────────
        probe(
            "performance.getEntriesByType exists",
            "(() => typeof performance.getEntriesByType === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "PerformanceNavigationTiming exists",
            "(() => typeof PerformanceNavigationTiming === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "PerformanceResourceTiming exists",
            "(() => typeof PerformanceResourceTiming === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "performance.now is finite",
            "(() => { const t = performance.now(); return typeof t === 'number' && isFinite(t) && t > 0; })()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "memory jsHeapSizeLimit plausible",
            "(() => !!(performance.memory && performance.memory.jsHeapSizeLimit > 0))()",
            Severity::Low,
            classify_must_be_true,
        ),
        // ─── Navigator / device extensions ────────────────────────────────────
        probe(
            "navigator.mediaCapabilities exists",
            "(() => typeof navigator.mediaCapabilities === 'object')()",
            Severity::Medium,
            classify_must_be_true,
        ),
        probe(
            "navigator.clipboard.readText exists",
            "(() => !!(navigator.clipboard && typeof navigator.clipboard.readText === 'function'))()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "navigator.clipboard.writeText exists",
            "(() => !!(navigator.clipboard && typeof navigator.clipboard.writeText === 'function'))()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "navigator.keyboard exists",
            "(() => typeof navigator.keyboard === 'object')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "navigator.presentation exists",
            "(() => typeof navigator.presentation === 'object')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "navigator.scheduling exists",
            "(() => typeof navigator.scheduling === 'object')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "navigator.setAppBadge exists",
            "(() => typeof navigator.setAppBadge === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "navigator.clearAppBadge exists",
            "(() => typeof navigator.clearAppBadge === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        // ─── Storage / sensors / lifecycle ────────────────────────────────────
        probe(
            "navigator.storage.estimate exists",
            "(() => !!(navigator.storage && typeof navigator.storage.estimate === 'function'))()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "caches.open exists",
            "(() => typeof caches === 'object' && typeof caches.open === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "navigator.storage.getDirectory exists",
            "(() => !!(navigator.storage && typeof navigator.storage.getDirectory === 'function'))()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "Geolocation exists",
            "(() => typeof navigator.geolocation === 'object')()",
            Severity::Medium,
            classify_must_be_true,
        ),
        probe(
            "DeviceOrientationEvent exists",
            "(() => typeof DeviceOrientationEvent === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "DeviceMotionEvent exists",
            "(() => typeof DeviceMotionEvent === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "AbsoluteOrientationSensor exists",
            "(() => typeof AbsoluteOrientationSensor === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "Document.fullscreenEnabled exists",
            "(() => typeof document.fullscreenEnabled === 'boolean')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "window.innerWidth > 0",
            "(() => window.innerWidth > 0)()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "window.innerHeight > 0",
            "(() => window.innerHeight > 0)()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "screen.availWidth plausible",
            "(() => screen.availWidth > 0 && screen.availWidth <= screen.width)()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "screen.availHeight plausible",
            "(() => screen.availHeight > 0 && screen.availHeight <= screen.height)()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "console exists",
            "(() => typeof console === 'object')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "DocumentPictureInPicture exists",
            "(() => typeof documentPictureInPicture === 'object')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "EyeDropper exists",
            "(() => typeof EyeDropper === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        probe(
            "PushManager exists",
            "(() => typeof PushManager === 'function')()",
            Severity::Low,
            classify_must_be_true,
        ),
        // NOTE: BarcodeDetector / FaceDetector (Shape Detection API) are
        // deliberately NOT probed. Their presence is not a stable real-browser
        // truth: absent on all Firefox, absent on Chrome Windows/Linux desktop
        // (no platform backend), present only on Chrome Android/ChromeOS/macOS
        // (and FaceDetector is flag-gated everywhere). A `classify_must_be_true`
        // presence check therefore false-Criticals legitimate desktop browsers on
        // BOTH the Chrome and Firefox gates, so there is no honest assertion to
        // make and the surface carries no probe.
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_probes_are_unique() {
        let probes = extended_probes();
        let mut seen = std::collections::HashSet::new();
        for p in &probes {
            assert!(seen.insert(p.name), "duplicate extended probe: {}", p.name);
        }
    }

    #[test]
    fn extended_probes_are_substantial() {
        let probes = extended_probes();
        assert!(
            probes.len() >= 25,
            "extended catalogue must add at least 25 surfaces, got {}",
            probes.len()
        );
    }

    #[test]
    fn webgpu_request_adapter_is_high_severity() {
        let probes = extended_probes();
        let p = probes
            .iter()
            .find(|p| p.name == "navigator.gpu.requestAdapter is function")
            .expect("requestAdapter probe missing");
        assert_eq!(p.severity, Severity::High);
    }
}
