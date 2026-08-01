//! Materialised profile overrides and override JavaScript.
//!
//! [`ProfileOverrides`] is the owned, pure-data fingerprint surface a
//! profile pins; [`profile_to_overrides`] builds it from the catalogue
//! and [`profile_js`] emits the CDP override script that pins those
//! values in-page.

use super::*;

/// The set of fingerprint values a profile pins.
///
/// Pure data - no IO. The CDP-bound [`apply_stealth_profile`]
/// reads this and produces the override JS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileOverrides {
    /// `navigator.userAgent` string (the anchor every other surface must cohere with).
    pub user_agent: String,
    /// `navigator.platform` value. Must match the UA's OS family.
    pub platform: String,
    /// `navigator.vendor` value. Empty for engines that do not expose a vendor.
    pub navigator_vendor: String,
    /// `navigator.languages` array.
    pub languages: Vec<String>,
    /// `userAgentData.brands` - Chromium-only. Empty for Firefox.
    pub brands: Vec<(String, String)>,
    /// `userAgentData.mobile` boolean.
    pub mobile: bool,
    /// `navigator.hardwareConcurrency`. Real desktops 4–16, mobile 6–8.
    pub hardware_concurrency: u32,
    /// `navigator.deviceMemory` GB.
    pub device_memory: u32,
    /// `screen.width`. Common desktop = 1920x1080.
    pub screen_width: u32,
    /// `screen.height` (paired with [`Self::screen_width`]).
    pub screen_height: u32,
    /// `screen.colorDepth` / `screen.pixelDepth`.
    pub color_depth: u8,
    /// WebGL `UNMASKED_VENDOR_WEBGL`. Must match the OS / hardware claimed by the UA.
    pub webgl_vendor: String,
    /// WebGL `UNMASKED_RENDERER_WEBGL` (paired with [`Self::webgl_vendor`]).
    pub webgl_renderer: String,
    /// IANA timezone the persona presents through `Intl`/`Date` (R056). Derived
    /// from the primary language so it is geographically coherent with
    /// [`Self::languages`]; [`profile_js`] injects a sound, DST-correct spoof that
    /// stops the browser leaking the host timezone. Override with
    /// [`Self::with_timezone`] to match a proxy's egress geography.
    pub timezone: String,
}

impl ProfileOverrides {
    /// Return these profile overrides presenting the given IANA timezone. Use this
    /// to align the persona's timezone with a proxy's egress geography (the
    /// operator-supplied side of [`crate::fingerprint::persona_geo_self_probe`]);
    /// the default is derived from the persona's primary language.
    #[must_use]
    pub fn with_timezone(mut self, timezone: impl Into<String>) -> Self {
        self.timezone = timezone.into();
        self
    }

    /// Return these profile overrides with hardware/display surfaces replaced.
    #[must_use]
    pub fn with_hardware(mut self, hardware: ProfileHardware) -> Self {
        self.hardware_concurrency = u32::from(hardware.hardware_concurrency);
        self.device_memory = u32::from(hardware.device_memory);
        self.screen_width = hardware.screen_width;
        self.screen_height = hardware.screen_height;
        self.color_depth = hardware.color_depth;
        self.webgl_vendor = hardware.webgl_vendor.into();
        self.webgl_renderer = hardware.webgl_renderer.into();
        self
    }
}

/// Materialise profile overrides using a deterministic hardware variant index.
#[must_use]
pub fn profile_to_overrides_at(
    profile: &StealthProfile,
    hardware_index: usize,
) -> ProfileOverrides {
    profile_to_overrides(profile).with_hardware(profile_hardware_at(*profile, hardware_index))
}

/// Firefox's REDUCED `navigator.appVersion` for a persona OS family.
///
/// Modern Firefox does NOT return `userAgent` minus `"Mozilla/"` for appVersion;
/// it returns the frozen OS-family form `"5.0 (Windows)"` / `"5.0 (Macintosh)"` /
/// `"5.0 (X11)"`. Verified live (FF 151 Linux → `"5.0 (X11)"`,
/// `tests/surface_truth_live.rs`). Emitting the full UA string (the old behavior)
/// is a value no real Firefox reports, a coherence tell. Derived from the persona
/// `navigator.platform` so it is correct whether the persona is matched-host or a
/// cross-OS injection, never the host's real OS.
///
/// Shared source of truth for BOTH the window-realm JS getter (emitted by
/// [`profile_js`]) AND the engine `general.appversion.override` pref (emitted by
/// `build_user_js`). The getter alone does NOT reach a Web Worker's
/// `WorkerNavigator.appVersion` (the worker snapshots the ENGINE value at creation),
/// so a cross-OS persona's worker leaked the host OS (`"5.0 (X11)"` under a Windows
/// UA, window/worker disagreeing (confirmed live, tests/worker_cross_os_live.rs)).
/// Driving the pref from this same function keeps window and worker byte-identical.
pub fn firefox_app_version(platform: &str) -> &'static str {
    let p = platform.to_ascii_lowercase();
    if p.contains("win") {
        "5.0 (Windows)"
    } else if p.contains("mac") {
        "5.0 (Macintosh)"
    } else {
        // Linux / X11 / other Unix (the only desktop Firefox engine family left).
        "5.0 (X11)"
    }
}

/// Firefox's `navigator.oscpu` is the OS token from the UA's platform comment:
/// `(X11; Linux x86_64; rv:N)` → `Linux x86_64`,
/// `(Windows NT 10.0; Win64; x64; rv:N)` → `Windows NT 10.0; Win64; x64`,
/// `(Macintosh; Intel Mac OS X 10.15; rv:N)` → `Intel Mac OS X 10.15`.
///
/// Deriving it FROM the persona UA guarantees the two surfaces always agree:
/// `oscpu` is a Firefox-specific, OS-stamped string fingerprinters cross-check
/// against the UA platform token, so a cross-OS persona that leaves the host
/// `oscpu` (e.g. a Windows UA reporting `oscpu="Linux x86_64"`) is trivially
/// unmasked (confirmed live, dump_cross_os_persona_truth). If the UA lacks the
/// standard parenthesised comment we map the OS family from `platform`: never
/// the host value (Law 10: no silent leak of the real OS).
fn firefox_oscpu(user_agent: &str, platform: &str) -> String {
    if let Some(start) = user_agent.find('(') {
        if let Some(end_rel) = user_agent[start + 1..].find(')') {
            let comment = &user_agent[start + 1..start + 1 + end_rel];
            // Drop the trailing "; rv:NNN" Gecko-version segment, then strip the
            // platform-family prefix Firefox omits from oscpu ("X11; " on Linux,
            // "Macintosh; " on macOS).
            let os = comment.split("; rv:").next().unwrap_or(comment).trim();
            let os = os.strip_prefix("X11; ").unwrap_or(os);
            let os = os.strip_prefix("Macintosh; ").unwrap_or(os).trim();
            if !os.is_empty() {
                return os.to_string();
            }
        }
    }
    let p = platform.to_ascii_lowercase();
    if p.contains("win") {
        "Windows NT 10.0; Win64; x64".to_string()
    } else if p.contains("mac") {
        "Intel Mac OS X 10.15".to_string()
    } else {
        "Linux x86_64".to_string()
    }
}

fn languages_from_facts(facts: ProfileFacts) -> Vec<String> {
    facts
        .languages
        .iter()
        .map(|language| (*language).to_string())
        .collect()
}

fn client_hint_brands_for_profile(profile: StealthProfile) -> Vec<(String, String)> {
    profile_client_hint_brands(profile)
        .iter()
        .map(|brand| (brand.brand.to_string(), brand.version.to_string()))
        .collect()
}

/// Materialise the override values for a given profile. Pure.
///
/// The profile catalogue owns browser identity data; this function only
/// converts that pure data into owned values used by CDP JavaScript and tests.
pub fn profile_to_overrides(profile: &StealthProfile) -> ProfileOverrides {
    let facts = profile_facts(*profile);
    let hardware = profile_hardware(*profile);
    // Default the persona timezone from its primary language so it is geographically
    // coherent with `navigator.languages` (R056); the operator can realign it to a
    // proxy's egress geography via `with_timezone`.
    let timezone = facts
        .languages
        .first()
        .map_or("America/New_York", |lang| default_timezone_for_locale(lang))
        .to_string();
    ProfileOverrides {
        user_agent: facts.user_agent.into(),
        platform: facts.platform.into(),
        navigator_vendor: profile_navigator_vendor(*profile).into(),
        languages: languages_from_facts(facts),
        brands: client_hint_brands_for_profile(*profile),
        mobile: facts.mobile,
        hardware_concurrency: u32::from(hardware.hardware_concurrency),
        device_memory: u32::from(hardware.device_memory),
        screen_width: hardware.screen_width,
        screen_height: hardware.screen_height,
        color_depth: hardware.color_depth,
        webgl_vendor: hardware.webgl_vendor.into(),
        webgl_renderer: hardware.webgl_renderer.into(),
        timezone,
    }
}

/// Native-function camouflage prelude, shared by every injected stealth
/// script (the generic `FIREFOX_STEALTH_JS` and this per-profile `profile_js`).
///
/// Every getter/method we install via `Object.defineProperty` or by replacing
/// a prototype method is an ordinary JS function whose `.toString()` would
/// otherwise reveal non-native source (e.g. `() => undefined`), a strong
/// tamper tell that fingerprinters (CreepJS, FingerprintJS) weight heavily and
/// that guise's own probe catalogue flags High-severity.
///
/// This prelude routes `Function.prototype.toString` through a `Proxy` over the
/// *current* implementation. Functions registered via `__seal(fn, label)`
/// report `function <label>() { [native code] }`; the proxy itself reports a
/// native `toString`; every other receiver is delegated to the previous
/// `toString`. Because each preload wraps whatever `Function.prototype.toString`
/// already is, multiple independent scripts chain correctly and a genuine
/// native function still yields its real source. The registry is a `WeakMap`,
/// so membership is invisible to property enumeration (no global tell).
///
/// Injected as plain statements inside each stealth IIFE; `__seal` is then in
/// scope for the rest of that script.
pub(crate) const NATIVE_SEAL_PRELUDE: &str = r#"
    const __native = new WeakMap();
    const __seal = (fn, label) => { try { __native.set(fn, label || (fn && fn.name) || ''); } catch (_) {} return fn; };
    try {
        const __prevToString = Function.prototype.toString;
        const __tsProxy = new Proxy(__prevToString, {
            apply(target, thisArg, args) {
                try {
                    if (__native.has(thisArg)) {
                        // Strip a get/set prefix: Firefox names a native accessor
                        // by its bare property, not by the JS getter name.
                        var __n = String(__native.get(thisArg)).replace(/^(?:get|set) /, '');
                        return 'function ' + __n + '() {\n    [native code]\n}';
                    }
                } catch (_) {}
                if (thisArg === __tsProxy) { return 'function toString() {\n    [native code]\n}'; }
                return Reflect.apply(target, thisArg, args);
            },
        });
        Function.prototype.toString = __tsProxy;
        __native.set(__tsProxy, 'toString');
    } catch (_) {}
"#;

/// Build the override JS for a given profile.
///
/// Distinct from `crate::guise::STEALTH_JS` - that's the generic
/// "remove headless tells" pass. This is the "pin a coherent
/// fingerprint" pass. Apply both: stealth first, profile second,
/// so profile wins on the navigator surfaces it overrides.
pub fn profile_js(overrides: &ProfileOverrides) -> String {
    // Law 10 / G261 + dedup: route through the shared infallible serializer rather
    // than an inline `.unwrap_or_else(|_| ["en-US","en"])` that would silently ship
    // the WRONG language fingerprint on a (crate-controlled, never-failing) serialize.
    let langs_json = json_array(&overrides.languages);
    // navigator.language (singular) must equal navigator.languages[0].
    let lang0_json =
        serde_json::json!(overrides.languages.first().map_or("en-US", String::as_str)).to_string();
    let client_hints = client_hints_from_overrides(overrides);
    let brands_json = client_hints
        .as_ref()
        .map(|hints| json_array(&hints.brands))
        .unwrap_or_else(|| "[]".into());
    let full_version_list_json = client_hints
        .as_ref()
        .map(|hints| json_array(&hints.full_version_list))
        .unwrap_or_else(|| "[]".into());
    let client_hint_platform_json = client_hints
        .as_ref()
        .map(|hints| serde_json::json!(hints.platform).to_string())
        .unwrap_or_else(|| serde_json::json!(overrides.platform).to_string());
    let platform_version_json = client_hints
        .as_ref()
        .map(|hints| serde_json::json!(hints.platform_version).to_string())
        .unwrap_or_else(|| r#""""#.into());
    let architecture_json = client_hints
        .as_ref()
        .map(|hints| serde_json::json!(hints.architecture).to_string())
        .unwrap_or_else(|| r#""""#.into());
    let bitness_json = client_hints
        .as_ref()
        .map(|hints| serde_json::json!(hints.bitness).to_string())
        .unwrap_or_else(|| r#""""#.into());
    let model_json = client_hints
        .as_ref()
        .map(|hints| serde_json::json!(hints.model).to_string())
        .unwrap_or_else(|| r#""""#.into());
    let ua_full_version_json = client_hints
        .as_ref()
        .map(|hints| serde_json::json!(hints.ua_full_version).to_string())
        .unwrap_or_else(|| r#""""#.into());
    let wow64 = client_hints.as_ref().is_some_and(|hints| hints.wow64);

    // `navigator.deviceMemory` is a Chromium-only API, real Firefox does not
    // expose it at all (the property is absent from Navigator.prototype). Pinning
    // it on a Firefox persona would ADD a property the engine never has, an
    // obvious cross-engine tell. Only emit the override for a Chromium persona
    // (one that carries client-hint brands); for Firefox, leave deviceMemory
    // genuinely absent.
    let device_memory_block = if client_hints.is_some() {
        // `deviceMemory` is CREATED here (absent on a real Firefox Navigator.proto),
        // so the descriptor's `enumerable` is whatever we set, and a real Chrome
        // WebIDL attribute is `enumerable: true`. Omitting it defaults to `false`,
        // a constructor-grade tell (`getOwnPropertyDescriptor(...).enumerable`).
        // Existing Firefox attributes preserve their native `true` on redefinition,
        // but a freshly-created property does not, so it must be set explicitly.
        format!(
            "        Object.defineProperty(Navigator.prototype, 'deviceMemory', {{\n\
             \x20           get: __seal(() => {dm}, 'get deviceMemory'),\n\
             \x20           enumerable: true,\n\
             \x20           configurable: true,\n\
             \x20       }});\n",
            dm = overrides.device_memory
        )
    } else {
        String::new()
    };

    // navigator.oscpu is the INVERSE of deviceMemory across the engine boundary:
    // a Firefox-only property the Firefox ENGINE exposes natively.
    //   * Chromium persona: Chrome has no `oscpu`, so leaving the engine's native
    //     one present is a cross-engine tell (`'oscpu' in navigator`). Delete it.
    //   * Firefox persona: pin it to the persona's OS token (derived from the UA)
    //     so a cross-OS persona stops leaking the HOST OS (a Windows UA otherwise
    //     reports `oscpu="Linux x86_64"`: confirmed live, dump_cross_os_persona_truth).
    let oscpu_block = if client_hints.is_some() {
        "        try { delete Navigator.prototype.oscpu; } catch (_) {}\n".to_string()
    } else {
        // Redefines an EXISTING native accessor, so omitting `enumerable` preserves
        // its native `true` (matches a real Firefox descriptor).
        format!(
            "        try {{ Object.defineProperty(Navigator.prototype, 'oscpu', {{\n\
             \x20           get: __seal(() => {oscpu_json}, 'get oscpu'),\n\
             \x20           configurable: true,\n\
             \x20       }}); }} catch (_) {{}}\n",
            oscpu_json =
                serde_json::json!(firefox_oscpu(&overrides.user_agent, &overrides.platform))
        )
    };

    // WebGL UNMASKED_RENDERER / UNMASKED_VENDOR (+ masked GL_RENDERER) spoof, emitted
    // ONLY for a NON-Gecko persona (Chrome/Safari). Those are injected onto a non-Gecko
    // engine that has no Firefox `webgl.override-unmasked-*` prefs, so this JS
    // getParameter override is the only spoof available. A FIREFOX persona OMITS it: the
    // engine prefs (`build_user_js`) cover EVERY realm, including a Web Worker's
    // OffscreenCanvas WebGL, which this WINDOW-realm getter cannot reach (the worker
    // leaked the real host GPU; confirmed live, tests/worker_webgl_cross_os_live.rs)
    // and route through Gecko's own SanitizeRenderer, the authentic form a raw getter
    // lacked. `if (REND_VAL)` keeps a matched-host persona on the native adapter.
    // Masked GL_VENDOR (0x1F00) is left native ("Mozilla" on every Firefox).
    let webgl_getter_block = if overrides.user_agent.contains("Firefox/") {
        String::new()
    } else {
        format!(
            r#"    try {{
        const REND_VAL = {rend};
        const VEND_VAL = {vend};
        if (REND_VAL) {{
            const UNMASKED_VENDOR = 0x9245, UNMASKED_RENDERER = 0x9246;
            const GL_RENDERER = 0x1F01;
            const wrap = (proto) => {{
                const orig = proto.getParameter;
                proto.getParameter = __seal(function getParameter(p) {{
                    if (p === UNMASKED_VENDOR) return VEND_VAL;
                    if (p === UNMASKED_RENDERER || p === GL_RENDERER) return REND_VAL;
                    return orig.call(this, p);
                }}, 'getParameter');
            }};
            if (typeof WebGLRenderingContext !== 'undefined') wrap(WebGLRenderingContext.prototype);
            if (typeof WebGL2RenderingContext !== 'undefined') wrap(WebGL2RenderingContext.prototype);
        }}
    }} catch (_) {{}}
"#,
            rend = serde_json::json!(overrides.webgl_renderer),
            vend = serde_json::json!(overrides.webgl_vendor),
        )
    };

    // speechSynthesis.getVoices() exposes the host OS's TTS voice list, on this
    // Linux host a ~13k-entry espeak-ng set (confirmed live,
    // dump_speech_and_datezone_truth). For a CROSS-OS persona that is a screaming
    // tell (thousands of espeak voices under a Windows/Mac UA, where a real machine
    // ships a small SAPI/Apple set). We cannot soundly FORGE a foreign voice set
    // (SpeechSynthesisVoice has no constructor, and the exact per-OS list needs
    // ground truth), so for a cross-OS persona we SUPPRESS the host list: getVoices()
    // returns [], a valid, common state (voices load async; TTS-less systems return
    // none) that reveals no host OS. Matched personas keep the native (coherent)
    // list. The non-empty persona renderer is the same cross-OS signal the WebGL
    // block keys on.
    let speech_block = if overrides.webgl_renderer.is_empty() {
        String::new()
    } else {
        "        try { var __sp = window.speechSynthesis; if (__sp) { var __sp_p = Object.getPrototypeOf(__sp); Object.defineProperty(__sp_p, 'getVoices', { value: __seal(function getVoices(){ return []; }, 'getVoices'), writable: true, configurable: true }); } } catch (_) {}\n".to_string()
    };

    // R056: pin the persona's locale + timezone so the browser stops leaking the
    // host locale/zone through Intl/Date/Number/String.
    let primary_locale = overrides.languages.first().map_or("en-US", String::as_str);
    let timezone_block = intl_spoof_js(primary_locale, &overrides.timezone);

    format!(
        r#"
(() => {{{seal_prelude}
    /* User-Agent + appVersion. userAgent is pinned to the persona; appVersion is
       the FROZEN OS-family form a real Firefox actually returns ("5.0 (X11)" /
       "5.0 (Windows)" / "5.0 (Macintosh)"). NOT userAgent-minus-"Mozilla/". The
       old full-UA form was a value no real Firefox reports (verified live), and it
       contradicted the bare engine AND the worker realm (which reports the frozen
       native form). Both are derived from the persona so a cross-engine detector
       sees a self-consistent, real-Firefox-shaped pair. */
    try {{
        Object.defineProperty(Navigator.prototype, 'userAgent', {{
            get: __seal(() => {ua_json}, 'get userAgent'),
            configurable: true,
        }});
        Object.defineProperty(Navigator.prototype, 'appVersion', {{
            get: __seal(() => {app_version_json}, 'get appVersion'),
            configurable: true,
        }});
    }} catch (_) {{}}

    /* navigator.platform - must agree with UA. Detectors flag
       (UA: Windows, platform: MacIntel) as obvious spoofing. */
    try {{
        Object.defineProperty(Navigator.prototype, 'platform', {{
            get: __seal(() => {platform_json}, 'get platform'),
            configurable: true,
        }});
    }} catch (_) {{}}

    /* navigator.vendor must match the browser engine family. */
    try {{
        Object.defineProperty(Navigator.prototype, 'vendor', {{
            get: __seal(() => {navigator_vendor_json}, 'get vendor'),
            configurable: true,
        }});
    }} catch (_) {{}}

    /* navigator.languages (plural) AND navigator.language (singular). Pinning
       only the plural is a tell: FingerprintJS/CreepJS cross-check that
       navigator.language === navigator.languages[0], so the singular must be
       overridden to the same primary tag or it leaks the host language. */
    try {{
        Object.defineProperty(Navigator.prototype, 'languages', {{
            get: __seal(() => {langs_json}, 'get languages'),
            configurable: true,
        }});
        Object.defineProperty(Navigator.prototype, 'language', {{
            get: __seal(() => {lang0_json}, 'get language'),
            configurable: true,
        }});
    }} catch (_) {{}}

    /* userAgentData - Chromium-only. Skip when brands is empty
       (Firefox profile). */
    try {{
        const brands = {brands_json};
        if (brands.length > 0) {{
            Object.defineProperty(Navigator.prototype, 'userAgentData', {{
                get: __seal(() => ({{
                    brands,
                    mobile: {mobile},
                    platform: {platform_json},
                    getHighEntropyValues: __seal((hints) => Promise.resolve({{
                        brands,
                        fullVersionList: {full_version_list_json},
                        mobile: {mobile},
                        platform: {client_hint_platform_json},
                        platformVersion: {platform_version_json},
                        architecture: {architecture_json},
                        bitness: {bitness_json},
                        model: {model_json},
                        uaFullVersion: {ua_full_version_json},
                        wow64: {wow64},
                    }}), 'getHighEntropyValues'),
                    toJSON: __seal(() => ({{ brands, mobile: {mobile}, platform: {client_hint_platform_json} }}), 'toJSON'),
                }}), 'get userAgentData'),
                enumerable: true,
                configurable: true,
            }});
        }}
    }} catch (_) {{}}

    /* hardwareConcurrency / deviceMemory - coherent with the
       claimed device class. */
    try {{
        Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {{
            get: __seal(() => {hwc}, 'get hardwareConcurrency'),
            configurable: true,
        }});
{device_memory_block}    }} catch (_) {{}}

    /* screen.* (width, height, availWidth, availHeight, colorDepth, pixelDepth)
       are deliberately NOT
       overridden. A real browser's screen dimensions AGREE with the CSS
       matchMedia layer (the `device-width`/`device-height` media features), but
       overriding the JS getters does NOT change what matchMedia reports, so a
       claimed screen size that differs from the real rendering surface is an
       INCONSISTENCY a detector flags (incolumitas MQ_SCREEN). A bare Firefox
       passes those media-query checks; leaving the real, self-consistent screen
       is strictly more coherent than a pinned-but-inconsistent one. */

    /* Window dimensions (inner/outer Width/Height, screenX/screenY) are
       deliberately NOT overridden (for the SAME reason as screen.* above).
       Verified live (tests/surface_truth_live.rs dump_geometry_truth): pinning
       window.innerWidth to the persona screen_width while the real window stays
       the screen-fit size produced a TRIPLE contradiction, innerWidth !=
       document.documentElement.clientWidth (the real layout viewport),
       matchMedia('(width)') reporting the real size not the persona, and
       innerWidth > screen.width (a window wider than its own screen). A
       JS getter cannot move the real layout/matchMedia/screen surfaces, so any
       pinned value that exceeds or disagrees with them is a trivially-detected
       tell. Leaving the real, self-consistent geometry (identical to a bare
       Firefox, which passes the matchMedia/clientWidth checks) is strictly more
       coherent. maxTouchPoints is a genuine capability signal (not a dimension
       contradicted by any layout surface) and is still pinned to the persona. */
    try {{
        Object.defineProperty(Navigator.prototype, 'maxTouchPoints', {{
            get: __seal(() => {max_touch_points}, 'get maxTouchPoints'),
            configurable: true,
        }});
    }} catch (_) {{}}

    /* navigator.oscpu - Firefox-only OS-stamped string; must agree with the UA's
       OS token (cross-OS personas otherwise leak the host OS) and be ABSENT for a
       Chromium persona (Chrome has no oscpu). See the oscpu_block above. */
{oscpu_block}

{webgl_getter_block}{speech_block}{timezone_block}}})();
"#,
        seal_prelude = NATIVE_SEAL_PRELUDE,
        timezone_block = timezone_block,
        speech_block = speech_block,
        ua_json = serde_json::json!(overrides.user_agent),
        app_version_json = serde_json::json!(firefox_app_version(&overrides.platform)),
        platform_json = serde_json::json!(overrides.platform),
        navigator_vendor_json = serde_json::json!(overrides.navigator_vendor),
        langs_json = langs_json,
        lang0_json = lang0_json,
        brands_json = brands_json,
        full_version_list_json = full_version_list_json,
        client_hint_platform_json = client_hint_platform_json,
        platform_version_json = platform_version_json,
        architecture_json = architecture_json,
        bitness_json = bitness_json,
        model_json = model_json,
        ua_full_version_json = ua_full_version_json,
        wow64 = wow64,
        mobile = overrides.mobile,
        hwc = overrides.hardware_concurrency,
        device_memory_block = device_memory_block,
        max_touch_points = if overrides.mobile { 5 } else { 0 },
        oscpu_block = oscpu_block,
        webgl_getter_block = webgl_getter_block,
    )
}

#[cfg(test)]
mod oscpu_unit {
    use super::firefox_oscpu;

    #[test]
    fn extracts_the_os_token_from_each_firefox_ua_family() {
        // Linux: the "X11; " platform prefix and "; rv:N" suffix are dropped.
        assert_eq!(
            firefox_oscpu(
                "Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0",
                "Linux x86_64"
            ),
            "Linux x86_64"
        );
        // Windows: the full NT token is kept (it IS the oscpu), suffix dropped.
        assert_eq!(
            firefox_oscpu(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
                "Win32"
            ),
            "Windows NT 10.0; Win64; x64"
        );
        // macOS: the "Macintosh; " prefix and suffix are dropped.
        assert_eq!(
            firefox_oscpu("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0", "MacIntel"),
            "Intel Mac OS X 10.15"
        );
    }

    #[test]
    fn never_returns_the_host_when_the_ua_is_malformed() {
        // No parenthesised comment → deterministic OS-family fallback keyed on the
        // persona platform, NEVER the host OS (Law 10: no silent host leak).
        assert_eq!(
            firefox_oscpu("not a real ua", "Win32"),
            "Windows NT 10.0; Win64; x64"
        );
        assert_eq!(
            firefox_oscpu("not a real ua", "MacIntel"),
            "Intel Mac OS X 10.15"
        );
        assert_eq!(
            firefox_oscpu("not a real ua", "Linux x86_64"),
            "Linux x86_64"
        );
        // Empty parens also fall back rather than returning "".
        assert_eq!(
            firefox_oscpu("Mozilla/5.0 () Firefox", "Win32"),
            "Windows NT 10.0; Win64; x64"
        );
    }

    #[test]
    fn windows_persona_oscpu_never_leaks_linux() {
        let oscpu = firefox_oscpu(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
            "Win32",
        );
        assert!(
            !oscpu.contains("Linux"),
            "windows persona oscpu leaked Linux: {oscpu}"
        );
    }
}
