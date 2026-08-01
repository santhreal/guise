//! Configurable browser fingerprint randomization for CDP-backed pages.
//!
//! The fixed stealth script in [`crate::cdp`] removes common automation tells.
//! This module adds caller-controlled session noise for high-entropy browser
//! fingerprint surfaces such as canvas, audio, fonts, timers, and hardware
//! counters. Use it when a caller needs deterministic per-session variation
//! in addition to a coherent profile.
//!
//! # Engine-redundancy audit (G084)
//!
//! The JS evasions below are the **stock-Firefox gap fillers**: they patch
//! surfaces the real browser exposes natively and the patched reynard engine
//! handles inside the engine. They intentionally do NOT re-implement persona
//! identity (`navigator.userAgent`, `navigator.platform`, `navigator.languages`,
//! screen geometry, `navigator.webdriver`, etc.), those belong to the profile
//! layer ([`crate::fingerprint::profiles`]) and, for reynard, to the engine
//! config ([`crate::browser::reynard_config`]). The launch-path audit in
//! `src/browser/mod.rs` enforces that reynard never calls this JS evasion layer,
//! avoiding double-spoof drift.

use anyhow::{anyhow, Result};
use runtime_foxdriver::Page;
use serde::{de::IntoDeserializer, Deserialize, Serialize};

mod js;
pub(crate) use js::*;

/// Fingerprint randomization configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintConfig {
    /// Noise level for canvas rendering, clamped to `0.0..=1.0` at injection.
    #[serde(default = "default_canvas_noise")]
    pub canvas_noise: f64,
    /// Normalize WebGL precision/extension readouts.
    ///
    /// Profile-specific vendor and renderer values are owned by
    /// [`super::profile_js`]; this flag keeps the other WebGL surfaces in a
    /// browser-shaped range without choosing a conflicting GPU identity.
    #[serde(default)]
    pub webgl_override: bool,
    /// Add noise to AudioContext analyzer fingerprints.
    #[serde(default = "default_true")]
    pub audio_noise: bool,
    /// Randomize font enumeration order and visibility.
    #[serde(default = "default_true")]
    pub font_noise: bool,
    /// Add noise to `performance.now()`.
    #[serde(default)]
    pub performance_noise: bool,
    /// Override hardware concurrency.
    #[serde(default)]
    pub hardware_concurrency: Option<u8>,
    /// Override device memory in GB.
    #[serde(default)]
    pub device_memory: Option<u8>,
    /// Seed for deterministic noise. The low 32 bits drive injected JS.
    #[serde(default)]
    pub seed: Option<u64>,
}

fn default_canvas_noise() -> f64 {
    0.02
}

fn default_true() -> bool {
    true
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            canvas_noise: 0.02,
            webgl_override: true,
            audio_noise: true,
            font_noise: true,
            performance_noise: false,
            hardware_concurrency: None,
            device_memory: None,
            seed: None,
        }
    }
}

impl FingerprintConfig {
    /// Minimal fingerprint randomization with only low canvas noise.
    pub fn minimal() -> Self {
        Self {
            canvas_noise: 0.01,
            webgl_override: false,
            audio_noise: false,
            font_noise: false,
            performance_noise: false,
            hardware_concurrency: None,
            device_memory: None,
            seed: None,
        }
    }

    /// Maximum built-in randomization.
    pub fn maximum() -> Self {
        Self {
            canvas_noise: 0.05,
            webgl_override: true,
            audio_noise: true,
            font_noise: true,
            performance_noise: true,
            hardware_concurrency: Some(8),
            device_memory: Some(8),
            seed: None,
        }
    }
}

/// Build the JS injected by [`apply_fingerprint`].
///
/// The returned string is deterministic for a fixed `config.seed`.
pub fn evasion_js_source(config: &FingerprintConfig) -> String {
    let seed = config.seed.unwrap_or_else(rand::random::<u64>);
    let seed32 = (seed & u64::from(u32::MAX)) as u32;
    let mut scripts = Vec::new();

    let canvas_noise = normalized_canvas_noise(config.canvas_noise);
    if canvas_noise > 0.0 {
        scripts.push(canvas_noise_js(seed32, canvas_noise));
    }

    if config.audio_noise {
        scripts.push(audio_noise_js(seed32));
    }

    if config.font_noise {
        scripts.push(font_noise_js(seed32));
    }

    if config.performance_noise {
        scripts.push(performance_noise_js(seed32));
    }

    if let Some(cores) = config.hardware_concurrency {
        scripts.push(hardware_concurrency_js(cores.clamp(1, 64)));
    }

    if let Some(mem) = config.device_memory {
        scripts.push(device_memory_js(mem.clamp(1, 64)));
    }

    if config.webgl_override {
        scripts.push(webgl_shape_js());
    }

    if scripts.is_empty() {
        return String::new();
    }

    // Prepend the shared native-camouflage prelude so every prototype method /
    // getter the evasion IIFEs install (toDataURL, getImageData, getChannelData, …)
    // is wrapped in `__seal(...)` and reports `[native code]` via `toString`. The
    // prelude defines `__seal` in the enclosing preload scope; the IIFEs below
    // reference it as a free variable (guarded by their own try/catch if ever
    // assembled without it). See [`super::NATIVE_SEAL_PRELUDE`].
    //
    // The scripts MUST be separated by `;`, not just `\n`. Each is an IIFE ending
    // in `})()`; two adjacent IIFEs joined by a bare newline are parsed by ASI as
    // `})()(function(){…})`: a call of the first IIFE's `undefined` return, which
    // throws `TypeError` and aborts the ENTIRE preload, silently disabling every
    // noise surface after the first. A trailing `;` terminates the last IIFE for
    // any caller that concatenates further script after this. Proven by the Node
    // behavioral oracle (`tests/evasion_farble_node_oracle.rs`).
    format!("{}\n{};\n", super::NATIVE_SEAL_PRELUDE, scripts.join(";\n"))
}

/// Apply fingerprint randomization to a page.
///
/// Call before navigation. The script is installed as a WebDriver BiDi
/// preload script (`add_preload_script`) so subsequent navigations on the
/// same page inherit it.
///
/// REALM SCOPE (stock-FF path): a BiDi preload runs in the window realm and in
/// child browsing contexts, same- AND cross-origin iframes inherit it (verified,
/// tests/iframe_cross_os_live.rs). It does NOT reach dedicated/Shared/Service
/// Workers, which are separate realms with their own `OffscreenCanvas` prototype. So
/// a Worker's CANVAS fingerprint is UNFARBLED on the JS path, confirmed live
/// (tests/worker_canvas_farble_live.rs): a persona's worker canvas hash equals the
/// BARE host's and disagrees with its own farbled window hash (a bypass + a
/// window-vs-worker tell + a stable host-canvas leak across personas). (AUDIO is NOT a
/// worker surface in Firefox: Workers do not expose `OfflineAudioContext`, confirmed
/// live, so the audio FP is window-only and there is no worker-audio hole to close.)
/// The canvas hole is NOT soundly closeable in JS: a `Worker`-constructor hook cannot
/// rewrite `new Worker('external.js')` (no source, and fetching breaks CSP/SRI), is
/// defeated entirely by NESTED workers (a worker spawned by a worker never sees a
/// window-realm hook), and is itself detectable. Engine-level farbling (reynard)
/// perturbs the TEXT-canvas via glyph spacing (`fonts:spacing_seed`) in EVERY realm
/// Workers included, closing the hole for text-based canvas FP (verified,
/// tests/reynard_canvas_audio_farble_live.rs); pure-SHAPE canvas stays unnoised
/// (`canvas:seed` has no engine reader). The identity ENGINE PREFS
/// (UA/platform/appVersion/WebGL renderer/timezone/hwc) DO reach Workers, only the
/// JS-getter farbles do not.
pub async fn apply_fingerprint(page: &Page, config: &FingerprintConfig) -> Result<()> {
    let script = evasion_js_source(config);
    if script.trim().is_empty() {
        return Ok(());
    }

    // Law 10 / G262: surface the failure, never bind-and-discard. The `?` already
    // propagates; the prior `let _ =` discarded only the `()` success but read as a
    // swallow and forced the apply-path audit to carry a `?`-exception carve-out
    // (carve-outs are where silent fallbacks hide). A plain statement keeps the
    // apply path uniformly free of `let _ =` on preload/evaluate calls.
    page.add_preload_script(&script)
        .await
        .map_err(|e| anyhow!("stealth fingerprint evasion injection failed: {e}"))?;
    Ok(())
}

/// Get current fingerprint signals from a page for debugging and verification.
pub async fn collect_signals(page: &Page) -> Result<FingerprintSignals> {
    let js = r#"(function() {
        const signals = {};

        try {
            const canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('fingerprint test', 2, 2);
            signals.canvas_hash = canvas.toDataURL().length;
        } catch(e) { signals.canvas_hash = -1; }

        try {
            const gl = document.createElement('canvas').getContext('webgl');
            const ext = gl && gl.getExtension('WEBGL_debug_renderer_info');
            signals.webgl_vendor = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : 'unknown';
            signals.webgl_renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : 'unknown';
        } catch(e) {
            signals.webgl_vendor = 'error';
            signals.webgl_renderer = 'error';
        }

        signals.user_agent = navigator.userAgent;
        signals.platform = navigator.platform;
        signals.language = navigator.language;
        signals.languages = navigator.languages ? Array.from(navigator.languages) : [];
        signals.hardware_concurrency = navigator.hardwareConcurrency || 0;
        signals.device_memory = navigator.deviceMemory || 0;
        signals.do_not_track = navigator.doNotTrack;

        signals.screen_width = screen.width;
        signals.screen_height = screen.height;
        signals.color_depth = screen.colorDepth;
        signals.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

        return signals;
    })()"#;

    let result = page.evaluate(js).await?;
    // Law 10 / G261: SURFACE a probe-deserialize failure, never coerce to `Null`.
    // The prior `.unwrap_or(Value::Null)` turned a failed read-back into a struct
    // of all-defaults (empty UA, `canvas_hash = -1`, empty platform) that a caller
    // verifying the page is stealthed cannot distinguish from a genuinely empty
    // page, the probe silently "succeeds" with fabricated signals. A read-back
    // that does not deserialize is a real failure and must be reported.
    let val: serde_json::Value = result.into_value().map_err(|e| {
        anyhow!("fingerprint-signal probe returned a result that did not deserialize as JSON: {e}")
    })?;

    parse_fingerprint_signals(val)
}

/// Parses the JSON read-back from the page into [`FingerprintSignals`], failing
/// closed if any expected field is missing or has the wrong type. This prevents
/// a partial probe from being silently coerced to defaults (e.g. `canvas_hash = -1`,
/// empty `user_agent`) and being mistaken for a successful stealth verification.
fn parse_fingerprint_signals(value: serde_json::Value) -> Result<FingerprintSignals> {
    // serde_json's bare type errors name no field ("invalid type: string,
    // expected u8"); track the path so an operator can find the bad signal.
    let de = value.into_deserializer();
    match serde_path_to_error::deserialize::<_, FingerprintSignals>(de) {
        Ok(signals) => Ok(signals),
        Err(e) => Err(anyhow!(
            "fingerprint-signal probe returned a JSON value that does not match FingerprintSignals at `{}`: {}",
            e.path(),
            e.inner()
        )),
    }
}

/// Collected browser fingerprint signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintSignals {
    /// Canvas fingerprint length from a deterministic test canvas.
    pub canvas_hash: i64,
    /// Reported WebGL vendor.
    pub webgl_vendor: String,
    /// Reported WebGL renderer.
    pub webgl_renderer: String,
    /// Reported navigator user agent.
    pub user_agent: String,
    /// Reported navigator platform.
    pub platform: String,
    /// Reported primary navigator language.
    pub language: String,
    /// Reported hardware concurrency.
    pub hardware_concurrency: u8,
    /// Reported device memory in GB.
    pub device_memory: u8,
    /// Reported screen width.
    pub screen_width: u32,
    /// Reported screen height.
    pub screen_height: u32,
    /// Reported screen color depth.
    pub color_depth: u8,
    /// Reported Intl timezone.
    pub timezone: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = FingerprintConfig::default();
        assert!((cfg.canvas_noise - 0.02).abs() < 0.001);
        assert!(cfg.webgl_override);
        assert!(cfg.audio_noise);
        assert!(cfg.font_noise);
    }

    #[test]
    fn minimal_config() {
        let cfg = FingerprintConfig::minimal();
        assert!((cfg.canvas_noise - 0.01).abs() < 0.001);
        assert!(!cfg.webgl_override);
        assert!(!cfg.audio_noise);
    }

    #[test]
    fn maximum_config() {
        let cfg = FingerprintConfig::maximum();
        assert!(cfg.performance_noise);
        assert_eq!(cfg.hardware_concurrency, Some(8));
        assert_eq!(cfg.device_memory, Some(8));
    }

    #[test]
    fn config_serde() {
        let cfg = FingerprintConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: FingerprintConfig = serde_json::from_str(&json).unwrap();
        assert!((restored.canvas_noise - cfg.canvas_noise).abs() < 0.001);
    }

    #[test]
    fn signals_serde() {
        let signals = FingerprintSignals {
            canvas_hash: 12345,
            webgl_vendor: "Google Inc. (NVIDIA)".into(),
            webgl_renderer: "ANGLE (NVIDIA, GeForce RTX 3060)".into(),
            user_agent: "Mozilla/5.0 Chrome/131".into(),
            platform: "Win32".into(),
            language: "en-US".into(),
            hardware_concurrency: 12,
            device_memory: 16,
            screen_width: 1920,
            screen_height: 1080,
            color_depth: 24,
            timezone: "America/New_York".into(),
        };
        let json = serde_json::to_string(&signals).unwrap();
        let restored: FingerprintSignals = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.canvas_hash, 12345);
        assert_eq!(restored.hardware_concurrency, 12);
    }

    #[test]
    fn config_from_json_with_defaults() {
        let json = r#"{"canvas_noise": 0.1}"#;
        let cfg: FingerprintConfig = serde_json::from_str(json).unwrap();
        assert!((cfg.canvas_noise - 0.1).abs() < 0.001);
        assert!(cfg.audio_noise);
        assert!(cfg.font_noise);
    }

    #[test]
    fn evasion_js_default_covers_configured_surfaces() {
        let cfg = FingerprintConfig {
            seed: Some(42),
            ..FingerprintConfig::default()
        };
        let js = evasion_js_source(&cfg);

        for needle in [
            "HTMLCanvasElement.prototype.toDataURL",
            "HTMLCanvasElement.prototype.toBlob",
            // The PRIMARY canvas-fingerprint path must be farbled at the source,
            // including the OffscreenCanvas bypass.
            "CanvasRenderingContext2D.prototype.getImageData",
            "OffscreenCanvasRenderingContext2D.prototype.getImageData",
            // The dominant font fingerprint (canvas measure-and-compare).
            "measureText",
            // Audio is patched at the buffer/analyser prototype, not via AudioContext.
            "AudioBuffer.prototype.getChannelData",
            "AnalyserNode.prototype",
            "WebGLRenderingContext",
            // getShaderPrecisionFormat is intentionally NOT patched, it is left
            // native (pass-through) to avoid an own-property descriptor tell; see
            // webgl_shape_js. Only the extension-list append remains.
            "getSupportedExtensions",
        ] {
            assert!(js.contains(needle), "missing {needle}");
        }
        assert!(
            !js.contains("getShaderPrecisionFormat"),
            "getShaderPrecisionFormat must stay native (pass-through), not be patched: {js}"
        );
    }

    #[test]
    fn evasion_js_minimal_skips_disabled_surfaces() {
        let cfg = FingerprintConfig {
            seed: Some(42),
            ..FingerprintConfig::minimal()
        };
        let js = evasion_js_source(&cfg);

        assert!(js.contains("HTMLCanvasElement.prototype.toDataURL"));
        assert!(!js.contains("getChannelData"));
        // measureText rides font_noise, which minimal() disables.
        assert!(!js.contains("measureText"));
        assert!(!js.contains("WebGLRenderingContext"));
    }

    #[test]
    fn evasion_js_does_not_reimplement_engine_or_identity_surfaces() {
        // G084: the JS evasion layer must stay in its lane. It adds noise to
        // canvas/audio/font/WebGL, but it must not re-implement persona identity
        // or engine-native spoofing, that would fight the profile layer on stock
        // Firefox and the engine layer on reynard.
        let cfg = FingerprintConfig {
            seed: Some(42),
            ..FingerprintConfig::default()
        };
        let js = evasion_js_source(&cfg);

        for forbidden in [
            "navigator.userAgent",
            "navigator.platform",
            "navigator.languages",
            "navigator.webdriver",
            "screen.width",
            "screen.height",
        ] {
            assert!(
                !js.contains(forbidden),
                "evasion JS must not reimplement identity/engine surface {forbidden}"
            );
        }
    }

    #[test]
    fn evasion_js_clamps_untrusted_numeric_inputs() {
        let cfg = FingerprintConfig {
            canvas_noise: f64::NAN,
            audio_noise: false,
            font_noise: false,
            performance_noise: false,
            webgl_override: false,
            hardware_concurrency: Some(255),
            device_memory: Some(0),
            seed: Some(42),
        };
        let js = evasion_js_source(&cfg);

        assert!(!js.contains("HTMLCanvasElement.prototype.toDataURL"));
        // Getters are sealed so their toString reports native; assert the
        // sealed form (see NATIVE_SEAL_PRELUDE).
        assert!(js.contains("get: __seal(() => 64, 'get hardwareConcurrency')"));
        assert!(js.contains("get: __seal(() => 1, 'get deviceMemory')"));
    }

    #[test]
    fn parse_fingerprint_signals_accepts_complete_json() {
        let val = serde_json::json!({
            "canvas_hash": 12345,
            "webgl_vendor": "Google Inc. (NVIDIA)",
            "webgl_renderer": "ANGLE (NVIDIA, GeForce RTX 3060)",
            "user_agent": "Mozilla/5.0 Chrome/131",
            "platform": "Win32",
            "language": "en-US",
            "hardware_concurrency": 12,
            "device_memory": 16,
            "screen_width": 1920,
            "screen_height": 1080,
            "color_depth": 24,
            "timezone": "America/New_York"
        });
        let signals = parse_fingerprint_signals(val).unwrap();
        assert_eq!(signals.canvas_hash, 12345);
        assert_eq!(signals.webgl_vendor, "Google Inc. (NVIDIA)");
        assert_eq!(signals.hardware_concurrency, 12);
        assert_eq!(signals.screen_width, 1920);
        assert_eq!(signals.timezone, "America/New_York");
    }

    #[test]
    fn parse_fingerprint_signals_rejects_missing_field() {
        let val = serde_json::json!({
            "canvas_hash": 12345
            // every other field missing
        });
        let err = parse_fingerprint_signals(val).unwrap_err().to_string();
        assert!(
            err.contains("missing field") || err.contains("FingerprintSignals"),
            "{err}"
        );
    }

    #[test]
    fn parse_fingerprint_signals_rejects_wrong_type() {
        let val = serde_json::json!({
            "canvas_hash": 12345,
            "webgl_vendor": "Google Inc. (NVIDIA)",
            "webgl_renderer": "ANGLE (NVIDIA, GeForce RTX 3060)",
            "user_agent": "Mozilla/5.0 Chrome/131",
            "platform": "Win32",
            "language": "en-US",
            "hardware_concurrency": "twelve",
            "device_memory": 16,
            "screen_width": 1920,
            "screen_height": 1080,
            "color_depth": 24,
            "timezone": "America/New_York"
        });
        let err = parse_fingerprint_signals(val).unwrap_err().to_string();
        assert!(err.contains("hardware_concurrency"), "{err}");
    }

    #[test]
    fn parse_fingerprint_signals_rejects_out_of_range_u8() {
        let val = serde_json::json!({
            "canvas_hash": 12345,
            "webgl_vendor": "Google Inc. (NVIDIA)",
            "webgl_renderer": "ANGLE (NVIDIA, GeForce RTX 3060)",
            "user_agent": "Mozilla/5.0 Chrome/131",
            "platform": "Win32",
            "language": "en-US",
            "hardware_concurrency": 300,
            "device_memory": 16,
            "screen_width": 1920,
            "screen_height": 1080,
            "color_depth": 24,
            "timezone": "America/New_York"
        });
        let err = parse_fingerprint_signals(val).unwrap_err().to_string();
        assert!(
            err.contains("hardware_concurrency") || err.contains("integer") || err.contains("u8"),
            "{err}"
        );
    }
}
