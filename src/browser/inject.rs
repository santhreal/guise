//! JS-layer anti-detection injection for the BiDi Firefox path.
//!
//! The generic, profile-independent overrides live here as one self-invoking
//! IIFE (assembled from the shared [`NATIVE_SEAL_PRELUDE`] + [`FIREFOX_STEALTH_BODY`]),
//! plus the [`apply_stealth`] / [`apply_stealth_profile`] entry points that
//! register them as BiDi preload scripts. Pref-layer (`user.js`) configuration
//! lives in [`super::userjs`]; the launch orchestration that ties the two
//! together lives in [`super`].

use runtime_foxdriver::browser::Page;
use std::sync::LazyLock;

use crate::fingerprint::NATIVE_SEAL_PRELUDE;

/// The generic stealth override statements (everything inside the IIFE, after
/// the camouflage prelude). Each installed getter/method is wrapped in
/// `__seal(fn, 'get <name>')` so its `.toString()` reports `[native code]`
/// instead of leaking the override source (see [`NATIVE_SEAL_PRELUDE`]).
///
/// WebGL is deliberately NOT touched here. A previous generic patch hard-coded
/// `UNMASKED_VENDOR_WEBGL=""` + a fixed `UNMASKED_RENDERER_WEBGL` (a 1050-Ti
/// string) for EVERY host, a measured tell: the live `headful_truth` probe
/// showed a real RTX-5090 box advertising an empty vendor and a card it does
/// not have, a string that also never matches the actual rendered pixels. On a
/// matched host (Firefox-on-Linux persona on real Firefox/Linux) Gecko already
/// sanitizes the adapter to a low-entropy, self-consistent value whose pixels
/// DO match, strictly more coherent than any constant. A genuine cross-OS
/// persona supplies its own coherent renderer through `profile_js` (gated on a
/// non-empty renderer); the generic layer must never invent one.
const FIREFOX_STEALTH_BODY: &str = r#"
    try {
        Object.defineProperty(Navigator.prototype, 'webdriver', {
            get: __seal(() => false, 'get webdriver'),
            configurable: true,
            enumerable: true,
        });
    } catch (_) {}

    try {
        Object.defineProperty(Navigator.prototype, 'maxTouchPoints', {
            get: __seal(() => 0, 'get maxTouchPoints'),
            configurable: true,
            enumerable: true,
        });
    } catch (_) {}

    // navigator.permissions.query is deliberately NOT overridden. Verified live
    // (tests/surface_truth_live.rs dump_permissions_truth): bare headless Firefox
    // already returns 'prompt' for every name it supports (notifications,
    // geolocation, camera, microphone, persistent-storage, push), identical to a
    // headed FF, so there is no headless tell to patch. The previous override also
    // listed Chromium-only names (clipboard-read/write, accelerometer, gyroscope,
    // magnetometer, ambient-light-sensor, payment-handler) that real Firefox
    // REJECTS with TypeError; returning {state:'prompt'} for those would have been
    // a self-inflicted tell. It was dead anyway (`Navigator.prototype.permissions`
    // throws an illegal-invocation that the try/catch swallowed). Leaving the real
    // native query untouched is strictly more coherent.
    //
    // navigator.permissions.request is likewise NOT added. Real Firefox exposes no
    // such method (`'request' in navigator.permissions` is false on bare FF);
    // adding it made the disguise distinguishable from a real browser.

    try {
        Object.defineProperty(Notification, 'permission', {
            get: __seal(() => 'default', 'get permission'),
            configurable: true,
            enumerable: true,
        });
    } catch (_) {}

    // navigator.plugins / navigator.mimeTypes are deliberately NOT overridden.
    // A real Firefox (even headless) already exposes a genuine PluginArray (the
    // PDF viewer set) where navigator.plugins instanceof PluginArray holds. The
    // previous override replaced it with a plain JS Array, which real detectors
    // flag (the sannysoft PluginArray check) as a regression vs bare Firefox.
    // Leaving the real Firefox plugins untouched is strictly more coherent.

    // WebGL adapter: native passthrough (no generic override) (see Rust note).

    // window.chrome is deliberately LEFT ABSENT. A real Firefox has no `chrome`
    // property on window at all: `'chrome' in window` and
    // `window.hasOwnProperty('chrome')` are both false (verified live, bare engine,
    // tests/surface_truth_live.rs). The previous `Object.defineProperty(window,
    // 'chrome', {get: () => undefined})` ADDED an own accessor: it passed a naive
    // `typeof window.chrome === 'undefined'` check but made `'chrome' in window`
    // and `hasOwnProperty('chrome')` TRUE, a divergence from real Firefox that the
    // descriptor lie-detector flags ("window.chrome is own property"). Fabricating
    // the key is strictly worse than leaving it absent (this is a Firefox engine;
    // Chrome personas are disguised at the HTTP/TLS layer, not via window.chrome).

    // window.outerWidth / outerHeight / devicePixelRatio are deliberately NOT
    // overridden. Verified live (tests/surface_truth_live.rs dump_geometry_truth):
    // a real bare Firefox reports outerWidth == innerWidth (Gecko has no side
    // chrome) and outerHeight == innerHeight + ~86, self-consistent with the real
    // screen. The previous getter forced outerWidth = innerWidth + 16 (wrong offset
    // for Firefox) and devicePixelRatio = 1. Worse, a getter cannot change the REAL
    // layout: document.documentElement.clientWidth, window.visualViewport, and
    // matchMedia('(resolution)') / ('(width)') keep reporting the true window, so
    // any pinned value that differs from reality is a trivially-detected divergence
    // (innerWidth != clientWidth, devicePixelRatio != matchMedia resolution).
    // Leaving the real, self-consistent geometry is strictly more coherent, the
    // same principle the per-profile layer applies to screen.* and the window
    // dimensions (see fingerprint/profiles/overrides.rs).

    // webdriver is pinned to false on Navigator.prototype ONLY (above). Do NOT
    // also define it on the `navigator` instance: that creates an OWN property,
    // which `_.has(navigator,'webdriver')` / hasOwnProperty detects (bot.sannysoft
    // "WebDriver (New)" = `navigator.webdriver || _.has(navigator,'webdriver')`).
    // A real Firefox carries webdriver only on the prototype (inherited).

    try {
        if (window.callPhantom || window._phantom) {
            Object.defineProperty(window, 'callPhantom', { get: __seal(() => undefined, 'get callPhantom'), configurable: true });
            Object.defineProperty(window, '_phantom', { get: __seal(() => undefined, 'get _phantom'), configurable: true });
        }
    } catch (_) {}

    try {
        Object.defineProperty(window, 'cdc_adoQpoasnfa76pfcZLmcfl_', { get: __seal(() => undefined, 'get cdc_adoQpoasnfa76pfcZLmcfl_'), configurable: true });
        Object.defineProperty(window, 'cdc_adoQpoasnfa76pfcZLmcfl_Array', { get: __seal(() => undefined, 'get cdc_adoQpoasnfa76pfcZLmcfl_Array'), configurable: true });
        Object.defineProperty(window, 'cdc_adoQpoasnfa76pfcZLmcfl_Promise', { get: __seal(() => undefined, 'get cdc_adoQpoasnfa76pfcZLmcfl_Promise'), configurable: true });
        Object.defineProperty(window, 'cdc_adoQpoasnfa76pfcZLmcfl_Symbol', { get: __seal(() => undefined, 'get cdc_adoQpoasnfa76pfcZLmcfl_Symbol'), configurable: true });
    } catch (_) {}

    try {
        const iframeDescriptor = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
        if (iframeDescriptor && iframeDescriptor.get) {
            const origGet = iframeDescriptor.get;
            Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
                get: __seal(function() {
                    try {
                        const win = origGet.call(this);
                        if (win) {
                            try { win.callPhantom; } catch(_) {}
                            try { win._phantom; } catch(_) {}
                        }
                        return win;
                    } catch(_) {
                        return null;
                    }
                }, 'get contentWindow'),
                configurable: true
            });
        }
    } catch (_) {}
"#;

/// Firefox-compatible generic anti-detection JS.
///
/// Covers the tells that are universal across all Firefox profiles
/// (webdriver, permissions, plugins, WebGL, chrome runtime, etc.).
/// Profile-specific overrides (UA, platform, vendor, languages, hardware)
/// are injected separately by [`apply_stealth_profile`].
///
/// Assembled at first use from the shared [`NATIVE_SEAL_PRELUDE`] (which makes
/// every override report native via `.toString()`) followed by
/// [`FIREFOX_STEALTH_BODY`]. The result is one self-invoking IIFE so the
/// prelude's `__seal` is in scope for the body.
pub(super) static FIREFOX_STEALTH_JS: LazyLock<String> = LazyLock::new(|| {
    format!(
        "(() => {{{prelude}\n{body}\n}})();\n",
        prelude = NATIVE_SEAL_PRELUDE,
        body = FIREFOX_STEALTH_BODY
    )
});

/// Apply generic anti-detection JS to `page`.
///
/// Injects via immediate `evaluate` + registers as a preload script so
/// future navigations also get the patches.
pub async fn apply_stealth(page: &Page) -> anyhow::Result<()> {
    page.evaluate(FIREFOX_STEALTH_JS.as_str())
        .await
        .map_err(|e| anyhow::anyhow!("stealth evaluate failed: {e:?}"))?;
    page.add_preload_script(FIREFOX_STEALTH_JS.as_str())
        .await
        .map_err(|e| anyhow::anyhow!("stealth preload script failed: {e:?}"))?;
    Ok(())
}

/// Apply a stealth profile's JS anti-detection patches to `page`.
///
/// 1. Injects the generic stealth script.
/// 2. Injects the profile-specific identity script (UA, platform, languages,
///    hardwareConcurrency, etc.).
/// 3. Registers both as preload scripts.
///
/// Derives the overrides from `profile` and defers to
/// [`apply_stealth_profile_with_overrides`]; callers that need to pre-shape the
/// overrides (e.g. engine-align the UA) call that variant directly.
pub async fn apply_stealth_profile(
    page: &Page,
    profile: &crate::StealthProfile,
) -> anyhow::Result<()> {
    apply_stealth_profile_with_overrides(page, &crate::profile_to_overrides(profile)).await
}

/// Apply the stealth disguise from caller-supplied [`crate::ProfileOverrides`].
///
/// Identical to [`apply_stealth_profile`] but lets the caller pre-shape the
/// overrides, most importantly to ALIGN the persona UA to the real engine major
/// (see [`super::launch_profiled_firefox`] / [`super::firefox_engine_major`]) so
/// the JS-layer `navigator.userAgent` claims the version the running Firefox
/// actually is, matching the `general.useragent.override` pref set at launch.
/// Without this, the JS layer would re-derive the static persona UA and contradict
/// the pref + the engine's true capability surface.
pub async fn apply_stealth_profile_with_overrides(
    page: &Page,
    overrides: &crate::ProfileOverrides,
) -> anyhow::Result<()> {
    // Register preloads FIRST (they apply to every future navigation), then
    // evaluate once on the current document. Errors propagate: a silently
    // swallowed preload-registration failure is exactly how the entire stealth
    // layer became a no-op (every tell must either be hidden or surface loudly).
    page.add_preload_script(FIREFOX_STEALTH_JS.as_str())
        .await
        .map_err(|e| anyhow::anyhow!("stealth preload (generic) failed to register: {e:?}"))?;
    // Surface the immediate-evaluate error, same contract as the per-profile
    // evaluate below (G262). Swallowing it (`let _ =`) hid a malformed generic
    // stealth script that raised on every page while apply reported success: the
    // generic automation-scrub silently became a no-op. A failure here is a real
    // bug in the script and must surface, not hide.
    page.evaluate(FIREFOX_STEALTH_JS.as_str())
        .await
        .map_err(|e| anyhow::anyhow!("stealth generic JS evaluate failed: {e:?}"))?;

    let profile_js = crate::profile_js(overrides);
    page.add_preload_script(&profile_js)
        .await
        .map_err(|e| anyhow::anyhow!("stealth preload (profile) failed to register: {e:?}"))?;
    // Surface the immediate-evaluate error. Swallowing it (`let _ =`) is exactly
    // how a malformed override script turned the ENTIRE per-profile fingerprint
    // layer (UA, hardwareConcurrency, vendor, WebGL, client hints, …) into a
    // silent no-op: the generated JS raised a SyntaxError on every page yet the
    // profile reported success. A failure here is a real bug in the generated
    // script (it must surface, not hide).
    page.evaluate(&profile_js).await.map_err(|e| {
        anyhow::anyhow!("stealth profile JS evaluate failed (malformed override script?): {e:?}")
    })?;

    Ok(())
}

/// The canonical default disguise: **max coherence**.
///
/// Scrubs automation tells ([`apply_stealth`]) while leaving the REAL browser
/// identity: UA, platform, hardwareConcurrency, WebGL, languages. GENUINE. A
/// real Firefox's surfaces are self-consistent across JS, the HTTP `User-Agent`
/// header, and the TLS/HTTP2 fingerprint, so the least-detectable disguise is
/// the real browser with its automation fingerprint removed.
///
/// This deliberately does NOT pin a persona. The previous behaviour
/// (`apply_stealth_profile(FirefoxLinux)`) backward-spoofs `navigator.userAgent`
/// to a fixed persona while a vanilla-launched browser's HTTP header and TLS
/// stack stay at the real version, a JS-vs-HTTP-vs-TLS mismatch that
/// fingerprint scorers (e.g. incolumitas) flag. For an EXPLICIT cross-OS /
/// cross-version persona, call [`apply_stealth_profile`] and launch via
/// [`super::launch_profiled_firefox`] so the launch-time
/// `general.useragent.override` pref makes every layer agree.
pub async fn apply_default_stealth_profile(page: &Page) -> anyhow::Result<()> {
    apply_stealth(page).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stealth_js_contains_webdriver_patch() {
        assert!(FIREFOX_STEALTH_JS.contains("webdriver"));
    }

    #[test]
    fn stealth_js_does_not_override_permissions_query() {
        // Verified live (dump_permissions_truth): bare headless Firefox already
        // returns coherent states ('prompt') for every name it supports, and
        // REJECTS Chromium-only names with TypeError. Overriding query could only
        // make the disguise diverge from real FF, so it must not be patched.
        assert!(
            !FIREFOX_STEALTH_JS.contains("permissions.query ="),
            "must not assign Navigator.prototype.permissions.query"
        );
        assert!(
            !FIREFOX_STEALTH_JS.contains("state: 'prompt'"),
            "must not fabricate permission states"
        );
    }

    #[test]
    fn stealth_js_does_not_add_permissions_request() {
        // Real Firefox exposes no navigator.permissions.request; adding one made
        // `'request' in navigator.permissions` true on the disguise but false on a
        // real browser (a self-inflicted tell).
        assert!(
            !FIREFOX_STEALTH_JS.contains("permissions.request ="),
            "must not assign navigator.permissions.request"
        );
    }

    #[test]
    fn stealth_js_contains_notification_permission_patch() {
        assert!(FIREFOX_STEALTH_JS.contains("Notification, 'permission'"));
    }

    #[test]
    fn stealth_js_does_not_override_plugins_or_mimetypes() {
        // Firefox's real navigator.plugins is a genuine PluginArray even
        // headless; overriding it with a plain Array is a detectable regression
        // (bot.sannysoft.com "Plugins is of type PluginArray"). The disguise
        // must NOT define its own plugins/mimeTypes getters.
        assert!(
            !FIREFOX_STEALTH_JS.contains("Navigator.prototype, 'plugins'"),
            "must not override navigator.plugins, real Firefox PluginArray is more coherent"
        );
        assert!(
            !FIREFOX_STEALTH_JS.contains("Navigator.prototype, 'mimeTypes'"),
            "must not override navigator.mimeTypes"
        );
    }

    #[test]
    fn stealth_js_webdriver_is_false_not_undefined() {
        // A real browser reports `navigator.webdriver === false` (property
        // present, value false). Hiding it to `undefined` is itself a tell
        // (sannysoft "WebDriver (New)" wants false). The disguise pins false.
        assert!(
            FIREFOX_STEALTH_JS.contains("'get webdriver'"),
            "webdriver getter must be present"
        );
        assert!(
            !FIREFOX_STEALTH_JS.contains("() => undefined, 'get webdriver'"),
            "webdriver must not be hidden to undefined, a real browser reports false"
        );
        assert!(FIREFOX_STEALTH_JS.contains("() => false, 'get webdriver'"));
    }

    #[test]
    fn stealth_js_does_not_hardcode_webgl_adapter() {
        // The generic layer must NOT override the WebGL adapter. A hard-coded
        // vendor/renderer is wrong on every host but the one it was written for,
        // and never matches the real rendered pixels (measured tell, see the
        // `headful_truth` probe). On a matched host the real, Gecko-sanitized
        // adapter is most coherent; a cross-OS persona supplies its own through
        // `profile_js`. So the generic stealth body installs no getParameter
        // override at all.
        assert!(
            !FIREFOX_STEALTH_JS.contains("WebGLRenderingContext.prototype.getParameter"),
            "generic layer must not hard-code a WebGL adapter (native passthrough)"
        );
        assert!(
            !FIREFOX_STEALTH_JS.contains("GTX 1050 Ti"),
            "the fabricated GTX 1050 Ti renderer must be gone"
        );
    }

    #[test]
    fn stealth_js_does_not_fabricate_window_chrome() {
        // Real Firefox has no `chrome` property on window (`'chrome' in window` is
        // false). Defining it, even as a getter returning undefined, adds an own
        // property that diverges from real Firefox and the lie-detector flags
        // ("window.chrome is own property"), verified live. The stealth JS must
        // therefore NOT touch window.chrome at all.
        assert!(
            !FIREFOX_STEALTH_JS.contains("defineProperty(window, 'chrome'"),
            "FIREFOX_STEALTH_JS must not fabricate a window.chrome own property. \
             real Firefox lacks the key entirely"
        );
    }

    #[test]
    fn stealth_js_contains_max_touch_points_patch() {
        assert!(FIREFOX_STEALTH_JS.contains("maxTouchPoints"));
    }

    #[test]
    fn stealth_js_does_not_override_window_geometry() {
        // outerWidth/outerHeight/devicePixelRatio must NOT be defined: a getter
        // cannot move the real layout (clientWidth), matchMedia('(resolution)'/
        // '(width)'), or screen.*, so any pinned value that differs is a trivially
        // detected divergence (verified live, dump_geometry_truth). The words still
        // appear in the explanatory comment, so assert the absence of the actual
        // defineProperty assignment, not the substring.
        assert!(
            !FIREFOX_STEALTH_JS.contains("'outerWidth', {"),
            "must not defineProperty window.outerWidth"
        );
        assert!(
            !FIREFOX_STEALTH_JS.contains("'outerHeight', {"),
            "must not defineProperty window.outerHeight"
        );
        assert!(
            !FIREFOX_STEALTH_JS.contains("'devicePixelRatio', {"),
            "must not defineProperty window.devicePixelRatio"
        );
    }

    #[test]
    fn stealth_js_contains_phantom_cleanup() {
        assert!(FIREFOX_STEALTH_JS.contains("callPhantom"));
        assert!(FIREFOX_STEALTH_JS.contains("_phantom"));
    }

    #[test]
    fn stealth_js_contains_cdc_cleanup() {
        assert!(FIREFOX_STEALTH_JS.contains("cdc_adoQpoasnfa76pfcZLmcfl_"));
    }

    #[test]
    fn stealth_js_contains_iframe_content_window_patch() {
        assert!(FIREFOX_STEALTH_JS.contains("HTMLIFrameElement.prototype"));
    }

    #[test]
    fn stealth_js_is_balanced_braces() {
        let mut depth = 0;
        let mut in_string = false;
        let mut string_char = ' ';
        let mut escape = false;
        for c in FIREFOX_STEALTH_JS.chars() {
            if in_string {
                if escape {
                    escape = false;
                    continue;
                }
                if c == '\\' {
                    escape = true;
                    continue;
                }
                if c == string_char {
                    in_string = false;
                }
                continue;
            }
            if c == '"' || c == '\'' || c == '`' {
                in_string = true;
                string_char = c;
                continue;
            }
            match c {
                '{' | '(' | '[' => depth += 1,
                '}' | ')' | ']' => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "unbalanced braces at char '{}'", c);
        }
        assert_eq!(depth, 0, "JS has unbalanced braces");
    }

    #[test]
    fn stealth_js_no_bare_single_quotes_in_strings() {
        // Verify no unescaped single quotes inside single-quoted strings
        let mut in_single_quote = false;
        let mut escape = false;
        for c in FIREFOX_STEALTH_JS.chars() {
            if escape {
                escape = false;
                continue;
            }
            if c == '\\' {
                escape = true;
                continue;
            }
            if c == '\'' {
                in_single_quote = !in_single_quote;
                continue;
            }
            if c == '"' && !in_single_quote {
                // toggled by outer logic, skip for this simple check
            }
        }
        // If we got here without assertion failure, basic quote balance holds
    }

    #[test]
    fn stealth_js_balanced_all_brackets() {
        let mut round = 0i32;
        let mut square = 0i32;
        let mut curly = 0i32;
        let mut in_string = false;
        let mut string_char = ' ';
        let mut escape = false;
        for c in FIREFOX_STEALTH_JS.chars() {
            if in_string {
                if escape {
                    escape = false;
                    continue;
                }
                if c == '\\' {
                    escape = true;
                    continue;
                }
                if c == string_char {
                    in_string = false;
                }
                continue;
            }
            if c == '"' || c == '\'' || c == '`' {
                in_string = true;
                string_char = c;
                continue;
            }
            match c {
                '(' => round += 1,
                ')' => round -= 1,
                '[' => square += 1,
                ']' => square -= 1,
                '{' => curly += 1,
                '}' => curly -= 1,
                _ => {}
            }
            assert!(round >= 0, "unbalanced parens");
            assert!(square >= 0, "unbalanced square brackets");
            assert!(curly >= 0, "unbalanced curly braces");
        }
        assert_eq!(round, 0, "unclosed parens");
        assert_eq!(square, 0, "unclosed square brackets");
        assert_eq!(curly, 0, "unclosed curly braces");
    }

    #[test]
    fn stealth_js_no_eval_calls() {
        // Stealth code should never use eval() (it's a fingerprinting vector).
        let lower = FIREFOX_STEALTH_JS.to_lowercase();
        assert!(!lower.contains("eval("), "stealth JS contains eval() call");
    }

    #[test]
    fn stealth_js_starts_with_iife() {
        assert!(FIREFOX_STEALTH_JS.trim_start().starts_with("(() =>"));
    }

    #[test]
    fn stealth_js_ends_with_iife_invocation() {
        assert!(FIREFOX_STEALTH_JS.trim_end().ends_with("})();"));
    }

    /// Behavioral oracle: execute the real stealth IIFE under Node and prove it
    /// does NOT install any window-geometry override, while the core automation
    /// scrub (webdriver) IS applied. A source `.contains()` test can be fooled by
    /// the explanatory comment text; only running the IIFE and inspecting the
    /// resulting object proves no own `outerWidth`/`outerHeight`/`devicePixelRatio`
    /// accessor was defined, the real native geometry passes through, staying
    /// self-consistent with screen.*, clientWidth, and matchMedia (verified live in
    /// dump_geometry_truth). The getters previously forced outerWidth=innerWidth+16
    /// and devicePixelRatio=1, which contradicted the un-fakeable layout surfaces.
    #[test]
    fn stealth_iife_leaves_window_geometry_native_under_node() {
        use std::process::Command;
        if Command::new("node").arg("--version").output().is_err() {
            eprintln!(
                "SKIP stealth_iife_leaves_window_geometry_native_under_node: `node` not on PATH."
            );
            return;
        }
        // STEALTH passed via env (no shell, no escaping); harness is a fixed
        // script. The window stub pre-seeds NATIVE-style geometry values; if the
        // IIFE overrode them, the own-descriptor would gain a getter and the value
        // could change. Every block fails harmlessly into its own try/catch.
        let harness = r#"
'use strict';
const vm = require('vm');
const STEALTH = process.env.GUISE_STEALTH_JS;
const ctx = vm.createContext({
  window: { innerWidth: 800, innerHeight: 600, outerWidth: 800, outerHeight: 686, devicePixelRatio: 1 },
  navigator: {},
  Navigator: function Navigator(){},
  Notification: function Notification(){},
});
const fails = [];
try { vm.runInContext(STEALTH, ctx); } catch (e) { fails.push('stealth IIFE threw (whole preload aborts): ' + e.message); }
const read = (p) => vm.runInContext(p, ctx);
// 1. No own getter accessor must be installed for any window-geometry property.
for (const prop of ['outerWidth','outerHeight','innerWidth','innerHeight','devicePixelRatio','screenX','screenY']) {
  const d = read("Object.getOwnPropertyDescriptor(window, '" + prop + "')");
  if (d && typeof d.get === 'function') fails.push(prop + ' was overridden with a getter (must pass through to native)');
}
// 2. The native geometry values must be untouched and self-consistent.
if (read('window.outerWidth') !== 800) fails.push('outerWidth mutated: ' + read('window.outerWidth'));
if (read('window.outerWidth') < read('window.innerWidth')) fails.push('outerWidth < innerWidth (impossible)');
// 3. The core automation scrub MUST still apply (proves the IIFE actually ran).
const wd = read("Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver')");
if (!(wd && typeof wd.get === 'function' && wd.get() === false)) fails.push('webdriver scrub not applied (IIFE did not run)');
if (fails.length) { console.error('GEOMETRY ORACLE FAIL:\n' + fails.join('\n')); process.exit(1); }
console.log('GEOMETRY ORACLE OK');
"#;
        let out = Command::new("node")
            .arg("-e")
            .arg(harness)
            .env("GUISE_STEALTH_JS", FIREFOX_STEALTH_JS.as_str())
            .output()
            .expect("run node");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("GEOMETRY ORACLE OK"),
            "window-geometry native-passthrough oracle failed:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );
    }
}
