//! Probe catalogue: the live fingerprint surfaces probed at runtime.

use super::catalogue_misc::misc_probes;
use super::classify::*;
use super::{Determinism, Probe, ProbeOutcome, Severity};
use crate::fingerprint::UserAgentBrowser;

/// Names of probes dropped when probing a **Firefox** disguise. Two categories:
///
/// 1. **Chromium-only** surfaces a real Firefox legitimately lacks (or reports
///    differently). These are replaced by [`firefox_probes`]'s inverse `… absent
///    (Firefox)` expectations, so the gate measures the disguise against the
///    *target* browser's real fingerprint instead of always against Chrome (a
///    Firefox persona that LEAKS one is a genuine Chromium-engine tell).
/// 2. **Conditional** surfaces (secure-context / platform / version / GPU-gated)
///    that Firefox MAY expose depending on version and OS, so there is no stable
///    Firefox truth in EITHER direction, these are dropped WITHOUT an inverse
///    (asserting presence OR absence would false-Critical a legitimate real
///    Firefox). They remain in the Chrome reference catalogue.
///
/// This is the data-driven contract behind family-aware probing. Add a name to
/// category 1 when a probe asserts a Chrome-specific surface Gecko never exposes;
/// add to category 2 when the surface's presence is genuinely engine-conditional.
pub(super) const CHROMIUM_ONLY_PROBES: &[&str] = &[
    "navigator.vendor non-empty",
    "navigator.userAgent",
    "navigator.productSub equals '20030107'",
    "window.chrome.runtime exists",
    "window.chrome.app.RunningState exists",
    "window.chrome.loadTimes returns object",
    "window.chrome.csi returns object",
    "navigator.getBattery() exists",
    "navigator.bluetooth exists",
    "navigator.usb exists",
    "navigator.hid exists",
    "navigator.serial exists",
    "navigator.getInstalledRelatedApps exists",
    "window.PaymentRequest exists",
    "navigator.share exists",
    "navigator.canShare exists",
    "window.cookieStore exists",
    "window.trustedTypes exists",
    "navigator.connection.effectiveType exists",
    "Reporting API exists",
    "Touch exists",
    // A Chrome-CDP-specific heuristic: it probes the Chrome DevTools port
    // (9222). Meaningless for a Firefox disguise (driven over BiDi on a private
    // port), so it is dropped for Firefox.
    "Chrome remote-debugging WS unreachable from page",
    // ── Chromium-only surfaces from the EXTENDED catalogue ──
    // These assert a surface via `classify_must_be_true`, which returns Critical
    // when absent. Each is a Blink/Chromium-only API a real Gecko build does NOT
    // expose, so leaving them in the Firefox catalogue made guise's OWN live
    // browser (Firefox/reynard) report a Critical on every one, false tells that
    // bury real findings and keep the Firefox gate from ever reading clean. They
    // are dropped for Firefox and replaced by the inverse "absent (Firefox)"
    // assertions in `catalogue_firefox` (a Firefox persona that LEAKS one is a
    // genuine Chromium-engine tell). `performance.memory` (jsHeapSizeLimit) is the
    // canonical example: a non-standard Chrome-only API Firefox has never shipped.
    "memory jsHeapSizeLimit plausible",
    "navigator.keyboard exists",
    "navigator.presentation exists",
    "navigator.scheduling exists",
    "navigator.setAppBadge exists",
    "navigator.clearAppBadge exists",
    "EyeDropper exists",
    "AbsoluteOrientationSensor exists",
    // ── Category 2: secure-context / platform / version-conditional ──
    // Firefox MAY expose these depending on version, OS, and GPU/secure-context
    // availability, so there is NO stable Firefox truth to assert either way:
    //   * WebGPU (`navigator.gpu` and friends) is OFF by default on Firefox
    //     Linux/macOS and in headless, and absent in any GPU-less environment, yet
    //     default-ON on Firefox Windows 141+. Verified ABSENT on the live
    //     FF-151-Linux engine even on a secure origin (tests/surface_truth_live.rs),
    //     so the `classify_must_be_true` presence checks were false-Criticals on
    //     guise's own browser. Dropped for Firefox WITHOUT an inverse (Firefox
    //     Windows legitimately has WebGPU, an "absent" assertion would itself be a
    //     false-Critical, the same mistake as the old DocumentPictureInPicture one).
    //   * Document Picture-in-Picture (`documentPictureInPicture`) ships in Firefox
    //     151 in a secure context, verified PRESENT on the live engine, so the
    //     surface is NOT Chromium-only; its old "absent (Firefox)" inverse was a
    //     false-Critical and was removed. Dropped without an inverse (presence is
    //     version-conditional on Firefox, so neither direction is stable).
    "navigator.gpu exists",
    "navigator.gpu.requestAdapter is function",
    "GPUAdapter.limits is object",
    "GPUBufferUsage exists",
    "navigator.gpu.getPreferredCanvasFormat exists",
    "DocumentPictureInPicture exists",
    // speechSynthesis voice COUNT is OS/environment-dependent on Firefox, not a
    // family truth: Firefox sources voices from the platform speech engine
    // (speech-dispatcher on Linux), so headless / Linux / CI Firefox legitimately
    // reports ZERO voices, and even desktop Firefox returns 0 synchronously until
    // the async `voiceschanged` event fires. Verified live: the BARE, un-stealthed
    // engine returns 0 (tests/probe_live.rs), so a `>= 4` assertion false-Drifts
    // guise's own real Firefox. Dropped for Firefox; kept in the Chrome reference
    // catalogue (Chrome bundles voices). No inverse, voice count is environmental,
    // not absent-by-engine.
    "speechSynthesis.getVoices returns >=16 voices",
];

/// Construct a probe with the boilerplate fields.
pub(super) fn probe(
    name: &'static str,
    js: &'static str,
    severity: Severity,
    classifier: fn(&serde_json::Value) -> ProbeOutcome,
) -> Probe {
    Probe {
        name,
        js,
        severity,
        classifier,
        // Catalogue surfaces are reproducible identity values (UA, platform, WebGL,
        // screen, …). Stochastic surfaces (timing/entropy) live in `redteam` and set
        // their own determinism.
        determinism: Determinism::Deterministic,
    }
}

/// The full probe catalogue for the default (Chromium) disguise: 100+ live
/// fingerprint surfaces, plus the `sear`-derived red-team probes (adversarial
/// sandbox-detection, inverted).
///
/// This is the back-compatible entry point (it measures against Chrome truth).
/// For a Firefox (or other family) disguise, use [`probes_for`] so the gate
/// validates the disguise against the *target* browser's real fingerprint
/// rather than Chrome's.
pub fn probes() -> Vec<Probe> {
    probes_for(UserAgentBrowser::Chrome)
}

/// The probe catalogue specialised for a target browser family.
///
/// The universal surfaces (DOM APIs, canvas/audio noise, automation-tell
/// scrubbing, the red-team set) are shared. Chromium-only surfaces (listed in
/// [`CHROMIUM_ONLY_PROBES`]) are kept for Chromium-family targets but dropped
/// for Firefox, where they would falsely flag legitimate Firefox absences
/// and replaced by [`firefox_probes`], which asserts the matching Firefox
/// truths (empty `vendor`, Gecko UA, `productSub` `20100101`, absent
/// `window.chrome`/`usb`/`PaymentRequest`/…, present `oscpu`).
///
/// guise's live browser is Firefox (driven over BiDi by `foxdriver`); the
/// Chrome profiles disguise the HTTP/TLS layer. So `probes_for(Firefox)` is the
/// correct oracle for the live stealth gate.
pub fn probes_for(browser: UserAgentBrowser) -> Vec<Probe> {
    let mut all = core_probes();
    all.extend(misc_probes());
    all.extend(super::catalogue_extended::extended_probes());
    all.extend(super::redteam::redteam_probes());
    all.extend(super::codec::codec_probes());
    all.extend(super::lie_detector::lie_detector_probes());
    all.extend(super::realm::realm_probes());
    all.extend(super::bidi_tells::bidi_tell_probes());
    all.extend(super::creepjs::creepjs_probes());
    if matches!(browser, UserAgentBrowser::Firefox) {
        all.retain(|p| !CHROMIUM_ONLY_PROBES.contains(&p.name));
        all.extend(super::catalogue_firefox::firefox_probes());
    }
    all
}

fn core_probes() -> Vec<Probe> {
    vec![
        // ─── Tier 0 - native-shape ────────────────────────────────────
        probe("Function.prototype.toString returns native code for Navigator.prototype.webdriver getter",
            "Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver').get.toString()",
            Severity::High,
            classify_must_be_native_code),
        probe("Function.prototype.toString native for WebGL getParameter",
            "WebGLRenderingContext.prototype.getParameter.toString()",
            Severity::High,
            classify_must_be_native_code),
        probe("Function.prototype.toString native for toDataURL",
            "HTMLCanvasElement.prototype.toDataURL.toString()",
            Severity::High,
            classify_must_be_native_code),
        // ─── Tier 1 - navigator basics ────────────────────────────────
        probe("navigator.webdriver",
            "navigator.webdriver === undefined ? null : navigator.webdriver",
            Severity::High,
            classify_webdriver_ok),
        // webdriver must be INHERITED (Navigator.prototype), never an OWN
        // property of the instance: `_.has`/hasOwnProperty exposes an own-prop
        // override (bot.sannysoft "WebDriver (New)").
        probe("navigator.webdriver is inherited, not an own property",
            "!Object.prototype.hasOwnProperty.call(navigator, 'webdriver')",
            Severity::High,
            classify_must_be_true),
        probe("navigator.plugins.length > 0",
            "(navigator.plugins || []).length",
            Severity::High,
            classify_must_be_nonzero_int),
        probe("navigator.plugins is a real PluginArray",
            "(() => { try { return (typeof PluginArray !== 'undefined') ? (navigator.plugins instanceof PluginArray) : true; } catch (_) { return false; } })()",
            Severity::High,
            classify_must_be_true),
        probe("navigator.mimeTypes.length > 0",
            "(navigator.mimeTypes || []).length",
            Severity::Medium,
            classify_must_be_nonzero_int),
        probe("navigator.languages.length > 0",
            "(navigator.languages || []).length",
            Severity::High,
            classify_must_be_nonzero_int),
        probe("navigator.language",
            "navigator.language",
            Severity::Low,
            classify_must_be_nonempty_string),
        probe("navigator.vendor non-empty",
            "navigator.vendor",
            Severity::Medium,
            classify_must_be_nonempty_string),
        probe("navigator.userAgent",
            "navigator.userAgent",
            Severity::High,
            classify_must_be_chromium_ua),
        probe("navigator.appVersion non-empty",
            "navigator.appVersion",
            Severity::Low,
            classify_must_be_nonempty_string),
        probe("navigator.platform non-empty",
            "navigator.platform",
            Severity::Medium,
            classify_must_be_nonempty_string),
        probe("navigator.cookieEnabled true",
            "navigator.cookieEnabled",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.onLine true",
            "navigator.onLine",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.pdfViewerEnabled true",
            "navigator.pdfViewerEnabled === true",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.product equals 'Gecko'",
            "navigator.product === 'Gecko'",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.productSub equals '20030107'",
            "navigator.productSub === '20030107'",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.appName equals 'Netscape'",
            "navigator.appName === 'Netscape'",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.appCodeName equals 'Mozilla'",
            "navigator.appCodeName === 'Mozilla'",
            Severity::Low,
            classify_must_be_true),
        // ─── Tier 1b - WebGL ──────────────────────────────────────────
        probe("WebGL UNMASKED_VENDOR not SwiftShader",
            "(() => { const c = document.createElement('canvas').getContext('webgl'); if (!c) return ''; const ext = c.getExtension('WEBGL_debug_renderer_info'); return ext ? c.getParameter(ext.UNMASKED_VENDOR_WEBGL) : ''; })()",
            Severity::High,
            classify_must_not_contain_swiftshader),
        probe("WebGL UNMASKED_RENDERER not SwiftShader",
            "(() => { const c = document.createElement('canvas').getContext('webgl'); if (!c) return ''; const ext = c.getExtension('WEBGL_debug_renderer_info'); return ext ? c.getParameter(ext.UNMASKED_RENDERER_WEBGL) : ''; })()",
            Severity::High,
            classify_must_not_contain_swiftshader),
        // ─── Tier 1c - Notification + Permissions ────────────────────
        probe("Notification.permission not 'denied'",
            "(() => { try { return Notification.permission !== 'denied'; } catch (_) { return false; } })()",
            Severity::Medium,
            classify_must_be_true),
        // ─── Tier 1d - chrome object ──────────────────────────────────
        probe("window.chrome.runtime exists",
            "(() => { try { return !!(window.chrome && window.chrome.runtime); } catch (_) { return false; } })()",
            Severity::High,
            classify_must_be_true),
        probe("window.chrome.app.RunningState exists",
            "(() => { try { return !!(window.chrome && window.chrome.app && window.chrome.app.RunningState); } catch (_) { return false; } })()",
            Severity::Medium,
            classify_must_be_true),
        probe("window.chrome.loadTimes returns object",
            "(() => { try { return typeof window.chrome.loadTimes === 'function' && typeof window.chrome.loadTimes() === 'object'; } catch (_) { return false; } })()",
            Severity::Medium,
            classify_must_be_true),
        probe("window.chrome.csi returns object",
            "(() => { try { return typeof window.chrome.csi === 'function' && typeof window.chrome.csi() === 'object'; } catch (_) { return false; } })()",
            Severity::Medium,
            classify_must_be_true),
        // ─── Tier 2a - canvas session-stability (no per-read tell) ────
        // These measure whether the canvas/audio surface is STABLE across two
        // reads in one session. A genuine browser is deterministic here, and so is
        // a correct farble (guise keys its perturbation on absolute coords/sample
        // index + a per-session seed). Per-read VARIATION is itself a tamper tell,
        // so instability is the Drift, stability the Pass (see
        // `classify_session_noise`), a real Firefox passes, a naive per-read
        // randomizer is caught. The RGB channels (the ones guise farbles) are
        // compared; alpha is excluded since it is intentionally left untouched.
        probe("CanvasRenderingContext2D getImageData session-stable (no per-read tell)",
            "(() => { const c = document.createElement('canvas'); c.width = c.height = 100; const ctx = c.getContext('2d'); ctx.fillStyle = 'red'; ctx.fillRect(0,0,100,100); const a = ctx.getImageData(0,0,100,100).data; const b = ctx.getImageData(0,0,100,100).data; let diff = 0; for (let i = 0; i < a.length; i += 4) { if (a[i] !== b[i] || a[i+1] !== b[i+1] || a[i+2] !== b[i+2]) diff++; } return diff > 0; })()",
            Severity::Medium,
            classify_session_noise),
        probe("HTMLCanvasElement.toDataURL session-stable (no per-read tell)",
            "(() => { const c = document.createElement('canvas'); c.width = c.height = 50; const ctx = c.getContext('2d'); ctx.fillStyle = 'blue'; ctx.fillRect(0,0,50,50); return c.toDataURL() !== c.toDataURL(); })()",
            Severity::Medium,
            classify_session_noise),
        // measureText (the font fingerprint) must also be session-stable: two
        // measures of the same string in the same session must agree (a uniform
        // per-session scale preserves this; a per-read perturbation would be a tell).
        probe("CanvasRenderingContext2D.measureText session-stable (no per-read tell)",
            "(() => { const c = document.createElement('canvas'); const ctx = c.getContext('2d'); ctx.font = '16px sans-serif'; return ctx.measureText('mwMW09_fingerprint').width !== ctx.measureText('mwMW09_fingerprint').width; })()",
            Severity::Low,
            classify_session_noise),
        // ─── Tier 2b - audio randomization (session strategy) ─────────
        probe("AudioBuffer.getChannelData session-stable (no per-read tell)",
            "(() => { try { const ctx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 100, 44100); const buf = ctx.createBuffer(1, 100, 44100); const a = Array.from(buf.getChannelData(0)); const b = Array.from(buf.getChannelData(0)); return JSON.stringify(a) !== JSON.stringify(b); } catch (_) { return false; } })()",
            Severity::Medium,
            classify_session_noise),
        // The AnalyserNode spectrum reader a detector exercises for the realtime
        // audio fingerprint. Present in both Chrome and Firefox; guise wraps it on
        // the prototype for farble, so this confirms it remains a callable function
        // (the wrapper's native-shape is proven separately by the Node oracle).
        probe("AnalyserNode.getFloatFrequencyData is a function",
            "(() => typeof AnalyserNode !== 'undefined' && !!AnalyserNode.prototype && typeof AnalyserNode.prototype.getFloatFrequencyData === 'function')()",
            Severity::Medium,
            classify_must_be_true),
        // ─── Tier 2c - WebRTC ─────────────────────────────────────────
        probe("RTCPeerConnection exists",
            "(() => typeof RTCPeerConnection !== 'undefined')()",
            Severity::Medium,
            classify_must_be_true),
        // The SDP-offer entry point a detector exercises to confirm a *real*
        // WebRTC stack (not just the constructor). Present in both Chrome and
        // Firefox wherever RTCPeerConnection is.
        probe("RTCPeerConnection.createOffer is a function",
            "(() => typeof RTCPeerConnection !== 'undefined' && typeof RTCPeerConnection.prototype.createOffer === 'function')()",
            Severity::Medium,
            classify_must_be_true),
        // ─── Tier 2d - hardware ──────────────────────────────────────
        probe("navigator.hardwareConcurrency in [2, 16]",
            "navigator.hardwareConcurrency",
            Severity::Low,
            classify_hardware_concurrency),
        probe("navigator.deviceMemory in [1, 64]",
            "navigator.deviceMemory || 8",
            Severity::Low,
            classify_device_memory),
        // ─── Tier 3 - peripheral APIs ────────────────────────────────
        probe("navigator.getBattery() exists",
            "(() => typeof Navigator.prototype.getBattery === 'function')()",
            Severity::Medium,
            classify_must_be_true),
        probe("navigator.permissions.query exists",
            "(() => !!(navigator.permissions && typeof navigator.permissions.query === 'function'))()",
            Severity::Medium,
            classify_must_be_true),
        probe("navigator.mediaDevices.enumerateDevices returns >=2",
            "(() => navigator.mediaDevices ? navigator.mediaDevices.enumerateDevices().then(d => d.length).catch(() => 0) : Promise.resolve(0))()",
            Severity::Medium,
            classify_must_be_nonzero_int),
        // getUserMedia is the camera/mic entry point a detector checks for a real
        // media stack. Guarded for context: when `mediaDevices` is absent (insecure
        // context) the probe passes, it only flags the tell where `mediaDevices`
        // exists but `getUserMedia` does not (an incoherent partial spoof).
        probe("navigator.mediaDevices.getUserMedia is a function",
            "(() => !navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia === 'function')()",
            Severity::Medium,
            classify_must_be_true),
        probe("navigator.bluetooth exists",
            "(() => typeof navigator.bluetooth === 'object')()",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.usb exists",
            "(() => typeof navigator.usb === 'object')()",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.hid exists",
            "(() => typeof navigator.hid === 'object')()",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.serial exists",
            "(() => typeof navigator.serial === 'object')()",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.getInstalledRelatedApps exists",
            "(() => typeof navigator.getInstalledRelatedApps === 'function')()",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.mediaSession exists",
            "(() => typeof navigator.mediaSession === 'object')()",
            Severity::Low,
            classify_must_be_true),
        probe("VideoDecoder exists",
            "(() => typeof VideoDecoder === 'function' && typeof VideoDecoder.isConfigSupported === 'function')()",
            Severity::Medium,
            classify_must_be_true),
        probe("VideoEncoder exists",
            "(() => typeof VideoEncoder === 'function' && typeof VideoEncoder.isConfigSupported === 'function')()",
            Severity::Medium,
            classify_must_be_true),
        probe("VideoFrame exists",
            "(() => typeof VideoFrame === 'function')()",
            Severity::Medium,
            classify_must_be_true),
        probe("MediaCapabilities.decodingInfo exists",
            "(() => !!(navigator.mediaCapabilities && typeof navigator.mediaCapabilities.decodingInfo === 'function'))()",
            Severity::Medium,
            classify_must_be_true),
        probe("navigator.wakeLock exists",
            "(() => typeof navigator.wakeLock === 'object')()",
            Severity::Low,
            classify_must_be_true),
        probe("window.PaymentRequest exists",
            "(() => typeof window.PaymentRequest === 'function')()",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.share exists",
            "(() => typeof navigator.share === 'function')()",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.canShare exists",
            "(() => typeof navigator.canShare === 'function')()",
            Severity::Low,
            classify_must_be_true),
        probe("navigator.serviceWorker exists",
            "(() => typeof navigator.serviceWorker === 'object')()",
            Severity::Medium,
            classify_must_be_true),
        probe("window.trustedTypes exists",
            "(() => typeof window.trustedTypes === 'object')()",
            Severity::Low,
            classify_must_be_true),
        probe("speechSynthesis.getVoices returns >=16 voices",
            "(() => (window.speechSynthesis ? window.speechSynthesis.getVoices().length : 0))()",
            Severity::Medium,
            classify_must_be_at_least_4_int),
        probe("window.visualViewport exists",
            "(() => typeof window.visualViewport === 'object')()",
            Severity::Low,
            classify_must_be_true),
        probe("window.cookieStore exists",
            "(() => typeof window.cookieStore === 'object')()",
            Severity::Low,
            classify_must_be_true),
        // ─── Tier 3e - screen surfaces ───────────────────────────────
        probe("screen.colorDepth == 24",
            "screen.colorDepth",
            Severity::Low,
            classify_color_depth),
        probe("screen.pixelDepth == 24",
            "screen.pixelDepth",
            Severity::Low,
            classify_color_depth),
        probe("screen.orientation.type exists",
            "(() => screen.orientation && typeof screen.orientation.type === 'string')()",
            Severity::Low,
            classify_must_be_true),
        probe("screen.width plausible",
            "screen.width",
            Severity::Low,
            classify_screen_size),
        probe("screen.height plausible",
            "screen.height",
            Severity::Low,
            classify_screen_size),
        probe("window.outerWidth >= innerWidth",
            "window.outerWidth >= window.innerWidth || window.outerWidth >= 100",
            Severity::Medium,
            classify_must_be_true),
        probe("window.outerHeight >= 100",
            "window.outerHeight >= 100",
            Severity::Medium,
            classify_must_be_true),
        // Physical containment invariants: a browser window cannot be larger than
        // the screen it lives on, and the viewport cannot exceed the screen. A
        // disguise that pins window.inner/outerWidth to a persona size larger than
        // the real screen (e.g. inner=1920 on a 1366-wide monitor) violates these 
        // a tell the `outerWidth >= innerWidth` probe above MISSES because it never
        // compares to screen.* (it stayed green while inner==outer==1920>screen).
        probe("window.outerWidth <= screen.width",
            "(() => window.outerWidth <= screen.width)()",
            Severity::High,
            classify_must_be_true),
        probe("window.outerHeight <= screen.height",
            "(() => window.outerHeight <= screen.height)()",
            Severity::High,
            classify_must_be_true),
        probe("window.innerWidth <= screen.width",
            "(() => window.innerWidth <= screen.width)()",
            Severity::High,
            classify_must_be_true),
        probe("window.innerHeight <= screen.height",
            "(() => window.innerHeight <= screen.height)()",
            Severity::High,
            classify_must_be_true),
        // Layout coherence: window.innerWidth (a JS getter, spoofable) must agree
        // with documentElement.clientWidth (the REAL layout viewport, NOT moved by
        // a getter override) within one scrollbar width. A pinned innerWidth that
        // the real layout does not match (the matchMedia-mismatch tell class) fails
        // here even when it would satisfy the containment checks on a large screen.
        probe("window.innerWidth matches layout clientWidth",
            "(() => { const c = (document && document.documentElement) ? document.documentElement.clientWidth : window.innerWidth; return Math.abs(window.innerWidth - c) <= 25; })()",
            Severity::High,
            classify_must_be_true),
        probe("window.devicePixelRatio sensible",
            "Math.round(window.devicePixelRatio)",
            Severity::Low,
            classify_dpr),
        // ─── Tier 3f - Performance ────────────────────────────────────
        probe("performance.now precision floored",
            "(() => { const a = performance.now(); for (let i=0;i<100;i++){}; const b = performance.now(); return (b - a) >= 0.1 || b === a; })()",
            Severity::Low,
            classify_must_be_true),
        // ─── Tier 3g - connection ────────────────────────────────────
        probe("navigator.connection.effectiveType exists",
            "(() => navigator.connection && typeof navigator.connection.effectiveType === 'string')()",
            Severity::Low,
            classify_must_be_true),
        // ─── Tier 3h - timezone / locale ─────────────────────────────
        // Intl.DateTimeFormat().resolvedOptions().timeZone is a heavily-weighted
        // fingerprint surface (FingerprintJS/CreepJS). We assert it resolves a
        // well-formed IANA id, not a specific zone, an EMPTY zone is the
        // stripped-ICU / headless tell. Universal across families.
        probe("Intl.DateTimeFormat resolves an IANA time zone",
            "(() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (_) { return ''; } })()",
            Severity::High,
            classify_iana_timezone),
        // ─── Tier 4 - CDP tells (Error.stack scrubbed) ───────────────
        probe("Error.stack does not leak puppeteer marker",
            "(() => { try { throw new Error('probe'); } catch (e) { return !/_puppeteer_evaluation_script_/.test(e.stack || ''); } })()",
            Severity::High,
            classify_must_be_true),
        probe("Error.stack does not leak cdpEvaluate marker",
            "(() => { try { throw new Error('probe'); } catch (e) { return !/_cdpEvaluate/.test(e.stack || ''); } })()",
            Severity::High,
            classify_must_be_true),
        // ─── Tier 4 - automation globals scrubbed ────────────────────
        probe("window.__nightmare undefined",
            "typeof window.__nightmare === 'undefined' ? null : window.__nightmare",
            Severity::Medium,
            classify_must_be_undefined),
        probe("window._phantom undefined",
            "typeof window._phantom === 'undefined' ? null : window._phantom",
            Severity::Medium,
            classify_must_be_undefined),
        probe("window.callPhantom undefined",
            "typeof window.callPhantom === 'undefined' ? null : window.callPhantom",
            Severity::Medium,
            classify_must_be_undefined),
        probe("window._selenium undefined",
            "typeof window._selenium === 'undefined' ? null : window._selenium",
            Severity::Medium,
            classify_must_be_undefined),
        // ─── Tier 4 - Chrome remote-debugging port not reachable from page JS ─
        // A real headless-detection heuristic: try to open a WebSocket to the
        // Chrome DevTools endpoint. If it OPENS, the debugging transport is
        // exposed to page script (automation leak); if it errors/closes (or
        // never connects within the budget) the port is unreachable, which is
        // what a normal browser, AND a correctly-driven CDP automation, both
        // present, because Chrome rejects DevTools WS upgrades that carry an
        // `Origin` header (every page-JS WebSocket does). The OLD probe used a
        // SYNCHRONOUS `new WebSocket(...); return false` which never reflects the
        // async connection outcome, it returned `false` for humans and bots
        // alike, so it always flagged critical. This async form actually tests
        // the surface. The BiDi runtime awaits the returned Promise
        // (`script.evaluate` with `awaitPromise`) by default.
        probe("Chrome remote-debugging WS unreachable from page",
            "(() => new Promise((resolve) => { \
                var settled = false; \
                var done = function (v) { if (!settled) { settled = true; resolve(v); } }; \
                try { \
                    var ws = new WebSocket('ws://127.0.0.1:9222/devtools/page/00000000000000000000000000000000'); \
                    ws.onopen = function () { try { ws.close(); } catch (_) {} done(false); }; \
                    ws.onerror = function () { done(true); }; \
                    ws.onclose = function () { done(true); }; \
                } catch (_) { done(true); } \
                setTimeout(function () { done(true); }, 700); \
            }))()",
            Severity::Medium,
            classify_must_be_true),
        // ─── Tier 5 - document timing ────────────────────────────────
        probe("document.head.children.length >= 1",
            "document.head ? document.head.children.length : 0",
            Severity::Low,
            classify_must_be_nonzero_int),
    ]
}
