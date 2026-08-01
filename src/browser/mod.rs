//! BiDi browser stealth application for Firefox + rustenium.
//!
//! Anti-detection JS is injected via BiDi `add_preload_script` + an immediate
//! `evaluate`. Firefox prefs (viewport, user-agent, etc.) are set at launch
//! time via `user.js`; this module ties the two layers together at launch.
//!
//! Responsibilities are split by layer:
//! - [`inject`] (the JS-runtime overrides (`apply_stealth`, `apply_stealth_profile`)).
//! - [`userjs`] (the launch-time Firefox pref builder (`build_user_js`)).
//! - [`reynard`] (engine-level spoof config for the patched Camoufox/reynard binary).
//!
//! The `launch_*` orchestration below composes them: build the pref file, launch
//! Firefox, then apply the JS + fingerprint layers so the BiDi path has the same
//! anti-detection coverage as the legacy CDP path.

use anyhow::Context;
use runtime_foxdriver::browser::{FoxBrowserConfig, Page};

use crate::fingerprint::{profile_user_agent, user_agent_facts, UserAgentBrowser};

mod inject;
mod reynard;
mod session_age;
mod userjs;

pub use inject::{
    apply_default_stealth_profile, apply_stealth, apply_stealth_profile,
    apply_stealth_profile_with_overrides,
};
pub use reynard::{
    align_ua_to_engine, firefox_engine_major, identity_seed, launch_reynard,
    launch_reynard_with_config, resolve_reynard_bin, reynard_config, reynard_config_env,
    REYNARD_CONFIG_ENV,
};
pub use session_age::{apply_session_age, generate_session_age, session_age_js, SessionAgeSeed};
pub use userjs::{automation_prefs, build_user_js};

/// Launch Firefox with the given profile applied at both the pref layer
/// (`user.js`) and the JS runtime layer (`evaluate` + `preload`).
///
/// Also applies the default fingerprint evasion (canvas noise, audio noise,
/// font noise, WebGL shaping) so the BiDi path matches the CDP path's
/// anti-detection coverage. Stock Firefox exposes these surfaces natively and
/// cannot spoof them through prefs alone, so the JS runtime layer is required
/// here, unlike the reynard path, which handles equivalent surfaces inside the
/// engine and therefore does not call this JS evasion layer.
/// The G092 engine-family gate as a PURE predicate: a Firefox-engine launcher must
/// refuse a non-Firefox persona (a Chromium/Safari/IE UA on Gecko is a hard
/// cross-layer tell). Returns the exact loud error a launch would, WITHOUT spawning
/// a browser, so the gate is unit-testable on any host (no real Firefox, no
/// flakiness). [`launch_profiled_firefox`] calls this before any process spawn.
pub(crate) fn firefox_engine_family_gate(profile: &crate::StealthProfile) -> anyhow::Result<()> {
    let family = user_agent_facts(profile_user_agent(*profile)).browser;
    if !matches!(family, UserAgentBrowser::Firefox) {
        return Err(anyhow::anyhow!(
            "launch_profiled_firefox only supports Firefox-family profiles; \
             {profile:?} ({family:?}) cannot be launched on a Firefox engine (G092)"
        ));
    }
    Ok(())
}

/// Launch Firefox with the given profile applied to the browser config.
///
/// # Errors
///
/// Returns an error when the browser cannot be launched or the profile fails to apply.
pub async fn launch_profiled_firefox(
    mut config: FoxBrowserConfig,
    profile: &crate::StealthProfile,
) -> anyhow::Result<Page> {
    // X007 / X045, enforce the unified persona coherence contract at the launch
    // boundary (the SAME primitive the reynard path and external launchers such as
    // captchaforge's `drive_browser` call): fail LOUD on an incoherent persona,
    // surface the proxyless host-TTL tell. See `enforce_persona_launch_coherence`.
    enforce_persona_launch_coherence(profile, config.proxy.is_none())?;

    // G092: this launcher drives a Firefox engine (stock Firefox or reynard).
    // A Chromium/Safari/IE persona launched on a Firefox engine is a hard cross-
    // layer tell, so fail loud instead of silently producing an incoherent browser.
    firefox_engine_family_gate(profile)?;

    let mut overrides = crate::profile_to_overrides(profile);
    // Align the persona UA to the REAL Firefox engine this launch runs on, the
    // same closure the reynard path applies. The static persona UA tracks the
    // modal TLS-impersonate (HTTP-client) profile; a live Firefox uses its OWN
    // Gecko TLS + version-gated JS, so the launched UA must claim the engine's
    // true major or navigator.userAgent disagrees with the capability surface
    // (the version-coherence tell). Best-effort: the configured binary (exact),
    // else PATH `firefox` (how rustenium resolves a `None` path); a no-op leaving
    // the valid persona UA if neither reports a parseable --version. The SAME
    // aligned overrides drive BOTH the `general.useragent.override` pref
    // (build_user_js) and the JS layer (apply_stealth_profile_with_overrides), so
    // every UA surface (pref, header, navigator (agrees on one version)).
    if let Some(major) =
        firefox_engine_major(config.executable_path.as_deref().unwrap_or("firefox"))
    {
        overrides.user_agent = align_ua_to_engine(&overrides.user_agent, major);
    }

    // Law 10: surface the cross-OS RENDERING tell. The stock-Firefox JS path spoofs
    // every JS-readable OS surface coherently, but ENGINE-RENDERED surfaces (font
    // enumeration, scrollbar width, canvas/audio) still come from the host, so a
    // persona whose OS differs from this host's leaks the real OS via those (confirmed
    // in tests/font_cross_os_live.rs + tests/cross_os_surface_sweep_live.rs). Loud
    // warn, never a silent ship; the reynard engine path is the coherent cross-OS
    // route and does NOT call this. See [`surface_cross_os_rendering_tell`].
    surface_cross_os_rendering_tell(&overrides);

    let user_js = build_user_js(&overrides);

    // Merge caller-supplied user.js with our profile prefs.
    config.user_js_content = Some(match config.user_js_content {
        Some(existing) => format!("{}\n{}", existing, user_js),
        None => user_js,
    });

    // G126 / R148: capture the identity key before `config` is consumed by
    // launch, so session-age seeding can be deterministic per account.
    let age_key: String = config
        .profile_dir
        .as_deref()
        .filter(|d| !d.is_empty())
        .unwrap_or("guise-default-session-age")
        .to_string();

    // Per-identity DEVICE fingerprint stability. When a `profile_dir` pins the
    // persona, derive the canvas/audio noise seed deterministically from it so a
    // returning profile reproduces the SAME device fingerprint across restarts.
    // A real returning user keeps one device; a fresh random seed every launch (the
    // `FingerprintConfig::default()` behaviour) would make the same logged-in
    // account present a NEW canvas/audio hash on each visit, a trivial
    // un-correlation tell that defeats the whole point of a persistent profile.
    // `None` (no profile_dir, i.e. an ephemeral one-shot persona) keeps the random
    // seed so each ephemeral launch is a distinct device.
    let persona_seed: Option<u64> = config
        .profile_dir
        .as_deref()
        .filter(|d| !d.is_empty())
        .map(identity_seed);

    // NB: `build_user_js` above ALWAYS emits persona prefs (general.useragent
    // .override, dom.maxHardwareConcurrency, the automation prefs), and those MUST
    // reach the engine: `dom.maxHardwareConcurrency`, for one, is what clamps the
    // Worker realm that the JS preload cannot reach. The self-managed launcher
    // guarantees this: it always creates a profile dir and fails closed if the
    // prefs cannot be written, so the persona is never silently half-applied.
    //
    // TZ: set the persona's IANA zone as a per-process env var on the Firefox
    // process. ICU reads TZ in EVERY realm, so `Intl.DateTimeFormat().resolved
    // Options().timeZone` and `Date.prototype.getTimezoneOffset` report the persona
    // zone in dedicated Workers too, the JS `Intl`/`Date` preload (window realm
    // only) cannot reach a Worker, so without this a Worker leaked the HOST zone
    // while the window claimed the persona's (a trivially-detected divergence,
    // confirmed live in tests/surface_truth_live.rs `dump_worker_timezone_truth`).
    // Per-process env (not the parent's) so concurrent launches with different
    // personas never race, this is why the stealth launch uses the self-managed
    // path (foxdriver owns the spawn); rustenium's managed launcher cannot set env.
    config
        .env
        .push(("TZ".to_string(), overrides.timezone.clone()));
    let page = runtime_foxdriver::browser::launch_firefox_self_managed(config).await?;
    apply_stealth_profile_with_overrides(&page, &overrides).await?;

    // Apply fingerprint evasion (canvas, audio, fonts, WebGL, performance)
    // so the BiDi path has the same surface coverage as the CDP path.
    // Law 10 / G262: propagate, never `let _ =`. Swallowing this returned a
    // HALF-STEALTHED page (canvas/audio/WebGL evasion silently absent, a
    // top-weighted fingerprint tell) while the caller saw `Ok(page)` as if fully
    // stealthed. It rides the same BiDi `add_preload_script` path that
    // `apply_stealth_profile` above just succeeded on, so it won't fire
    // spuriously; if it ever does, failing closed beats shipping a detectable page.
    // Stable per-identity device fingerprint for a pinned profile (see `persona_seed`).
    let fp_config = crate::fingerprint::FingerprintConfig {
        seed: persona_seed,
        ..crate::fingerprint::FingerprintConfig::default()
    };
    crate::fingerprint::apply_fingerprint(&page, &fp_config).await?;

    // G126 / R148: seed a plausible session age so a fresh profile does not
    // broadcast `history.length == 0` and an empty localStorage. Deterministic
    // per identity when a profile_dir is supplied; otherwise a sensible default
    // seed is used so every launch is protected.
    let session_age = generate_session_age(identity_seed(&age_key) % 1_000_000);
    apply_session_age(&page, &session_age)
        .await
        .context("launch_profiled_firefox: apply session age")?;

    Ok(page)
}

/// Launch Firefox with the default stealth profile.
pub async fn launch_default_profiled_firefox(config: FoxBrowserConfig) -> anyhow::Result<Page> {
    launch_profiled_firefox(config, &crate::StealthProfile::FirefoxLinux).await
}

/// Enforce the unified persona coherence contract for a launch (X007 / X045), the
/// SINGLE primitive every persona-launch path calls: guise's own
/// [`launch_profiled_firefox`] + [`launch_reynard_with_config`], and external
/// launchers (e.g. captchaforge's `drive_browser`) that spawn a foxdriver `Page`
/// directly. Centralising it here means the contract is enforced identically
/// wherever a persona meets a browser, no path can quietly skip it (the gap this
/// closed was exactly that: the gate existed, fully tested, but NO launch path
/// called it, so an incoherent persona could launch undetected).
///
/// Two parts:
/// 1. **Hard gate**: [`persona_full_stack_coherence`]: a persona that is not
///    self-consistent JS-to-wire (UA-OS == TLS-OS == TCP-OS, UA↔platform↔WebGL↔
///    Client-Hint, H2↔header↔browser↔TLS family) is REFUSED with an `Err`; spending
///    a browser launch on a detectable identity is never correct.
/// 2. **Law-10 host tell**: [`surface_host_network_tell`]: a loud `warn!` (never a
///    silent swallow, never a hard fail) when a *proxyless* egress host's TCP/IP
///    stack would betray the persona's claimed OS.
///
/// `proxyless` is `config.proxy.is_none()`: true when no egress proxy fronts the
/// launch, so the host's own initial TTL reaches the destination.
///
/// # Errors
/// Returns the persona incoherence (wrapped with launch context) when the hard gate
/// rejects `profile`.
pub fn enforce_persona_launch_coherence(
    profile: &crate::StealthProfile,
    proxyless: bool,
) -> anyhow::Result<()> {
    crate::http::session_coherence::persona_full_stack_coherence(*profile).map_err(|e| {
        anyhow::anyhow!("refusing to launch persona {profile:?}: incoherent fingerprint. {e}")
    })?;
    surface_host_network_tell(proxyless, profile);
    Ok(())
}

/// Surface the host-vs-persona TCP/IP-stack tell (X007 transport half / Law 10) at
/// a launch boundary. Shared by every persona-launch entry point so the surfacing
/// is identical (no per-call drift).
///
/// The host's own kernel stamps the initial IP TTL on outbound packets, so a
/// persona claiming an OS whose TTL differs from this host's (a Windows persona,
/// TTL 128, on a Linux host that stamps 64) is betrayed at the IP layer. UNLESS a
/// remote proxy fronts egress (the destination then sees the proxy's TTL). This
/// emits a loud `warn!` only when the persona's OS mismatches a *proxyless* host's
/// stack: never a silent swallow (Law 10), never a hard fail (the operator may
/// normalize egress out of band, and the proxy-present case is genuinely fine).
///
/// TTL source precedence is strict accuracy ordering, not a silent degradation:
/// the live `ip_default_ttl` (catches a kernel retuned to mimic another OS) is
/// preferred over the OS-family default; an unmodeled host yields `None` and we
/// then say nothing rather than assert a mismatch we cannot substantiate.
fn surface_host_network_tell(proxyless: bool, profile: &crate::StealthProfile) {
    if !proxyless {
        return;
    }
    use crate::http::session_coherence::{configured_host_initial_ttl, host_initial_ttl};
    let Some(host_ttl) = configured_host_initial_ttl().or_else(host_initial_ttl) else {
        return;
    };
    if let crate::fingerprint::NetworkOsCoherence::Mismatch {
        expected_os,
        expected_ttl,
        observed_initial_ttl,
    } = crate::fingerprint::os_network_coherence(*profile, host_ttl)
    {
        tracing::warn!(
            "persona {profile:?} claims {expected_os:?} (initial TTL {expected_ttl}) but this \
             proxyless egress host's TCP/IP stack stamps TTL {observed_initial_ttl}, the IP \
             layer will betray the persona. Front the launch with a TCP-OS-normalizing proxy, \
             or match the persona to the host OS."
        );
    }
}

/// True when a persona's `navigator.platform` indicates a different OS family than
/// `host_os` (in `std::env::consts::OS` form: `"windows"` / `"macos"` / `"linux"`).
///
/// Pure so it is unit-testable without launching a browser;
/// [`surface_cross_os_rendering_tell`] wraps it with the live host OS and the warn.
/// An unrecognized persona platform (`"other"`) makes no claim (returns `false`)
/// rather than asserting a mismatch we cannot substantiate.
pub(crate) fn cross_os_rendering_mismatch(persona_platform: &str, host_os: &str) -> bool {
    fn family(s: &str) -> &'static str {
        if s.contains("Win") {
            "windows"
        } else if s.contains("Mac") {
            "macos"
        } else if s.contains("Linux") || s.contains("X11") {
            "linux"
        } else {
            "other"
        }
    }
    let persona = family(persona_platform);
    persona != "other" && persona != host_os
}

/// Surface the cross-OS RENDERING tell at a STOCK-Firefox launch boundary (Law 10).
/// Called only by [`launch_profiled_firefox`]. NOT by the shared
/// [`enforce_persona_launch_coherence`] gate, because the reynard launch path handles
/// these surfaces at the engine level and must not trip this.
///
/// A class of OS-correlated surfaces is RENDERED by the engine, not read from a
/// JS-settable value, so the stock-FF JS path cannot SOUNDLY spoof them for a
/// foreign-OS persona, faking the JS-readable value mismatches what the engine
/// actually renders (a pixel/layout oracle disproves it). Confirmed live on a
/// FirefoxWindows persona on a Linux host:
///   * **Font enumeration** (`measureText`/`offsetWidth`/`document.fonts`) reports the
///     host's installed fonts: Windows persona shows DejaVu/Liberation/Ubuntu and
///     ZERO Windows fonts (tests/font_cross_os_live.rs).
///   * **Scrollbar width** is the host toolkit's (GTK ~12 px) not Windows' (~17 px
///     classic / 0 overlay) (tests/cross_os_surface_sweep_live.rs).
///   * Canvas/audio BASE glyph + sample rendering come from the host stack, the JS path
///     farbles the READOUT per-session (defeating cross-session linkage) but cannot
///     re-render the target OS's glyph shapes, so the foreign-OS tell remains.
///   * **WebGL deep parameters**: `getSupportedExtensions()`, the `MAX_*` numeric
///     limits, and integer shader precision, come from the host GL DRIVER, not the
///     spoofed adapter. The renderer/vendor STRINGS are pinned to a persona-coherent
///     ANGLE/Direct3D adapter, but the extension list and limits remain the host's:
///     confirmed live (tests/webgl_deep_params_cross_os_live.rs), a FirefoxWindows
///     persona claims `ANGLE (Intel … Direct3D11 …)` while reporting the host NVIDIA
///     driver's limits (`MAX_COMBINED_TEXTURE_IMAGE_UNITS:192`, `MAX_VIEWPORT_DIMS
///     [32768,32768]`). This is NOT soundly JS-spoofable, advertising an extension
///     the real driver lacks fails the instant a page calls `getExtension()` on it,
///     and faking a larger `MAX_TEXTURE_SIZE` fails at allocation (a behavioural
///     oracle disproves the lie). (Shader precision is left NATIVE/pass-through, see
///     `webgl_shape_js`: normalizing it created own-property descriptor tells for no
///     desktop benefit, so the real, self-consistent values flow through instead.)
///   * **WebGPU presence** (`navigator.gpu`) is ENGINE/OS-conditional and reflects the
///     HOST, not the persona OS: confirmed live (tests/webgpu_cross_os_live.rs)
///     `navigator.gpu` is ABSENT on this Linux host, so a FirefoxWindows persona lacks
///     it while a real Windows FF (WebGPU default-on since FF 141) HAS it: a cross-OS
///     PRESENCE tell. NOT soundly JS-spoofable (WebGPU is a large async API, a faked
///     `navigator.gpu` fails the instant `requestAdapter().requestDevice()`/buffer ops
///     run, and the adapter `info`/limits would have to match a real Windows GPU). Needs
///     the matching host OS or an engine-level WebGPU enable+spoof.
///
/// (The JS-READABLE OS surfaces. UA, platform, oscpu, appVersion, timezone, WebGL
/// vendor/renderer STRINGS, hardwareConcurrency, maxTouchPoints. ARE spoofed
/// coherently; the rendered surfaces and the WebGL deep-parameter SET remain.)
/// reynard improves SOME of these at the engine level, the font WHITELIST (which
/// families enumerate), the GL strings/parameters, AND it DOES farble the audio FP
/// (`audio:seed`) and perturb the TEXT-canvas FP via glyph spacing
/// (`fonts:spacing_seed`), reaching EVERY realm including Workers (verified
/// tests/reynard_canvas_audio_farble_live.rs). But that farble buys per-identity
/// UNLINKABILITY, a Windows persona's canvas/audio is the host base PLUS a per-identity
/// seed, so it is NOT byte-equal to the bare host and NOT linkable across sessions, it
/// is NOT cross-OS MIMICRY: reynard does not swap in the target OS's glyph OUTLINES or
/// font METRICS, and pure-SHAPE (non-text) canvas is unnoised (`canvas:seed` has no
/// engine reader). So a reynard Windows persona's text canvas is Linux glyphs + noise
/// it matches NO real Windows machine, and font enumeration still shows the host's Linux
/// families. The cross-OS RENDERING tell therefore REMAINS even under reynard. Fully
/// coherent cross-OS rendering needs the real target-OS rendering stack. This emits a
/// loud `warn!` (never a silent swallow) so the operator matches the persona to the host
/// OS (the only fully coherent option for the rendered surfaces) or accepts/closes the
/// residual deliberately.
fn surface_cross_os_rendering_tell(overrides: &crate::ProfileOverrides) {
    if cross_os_rendering_mismatch(&overrides.platform, std::env::consts::OS) {
        tracing::warn!(
            "persona platform {:?} differs from this host OS ({}) on the stock-Firefox path: \
             ENGINE-RENDERED surfaces still betray the real OS, font enumeration \
             (measureText/offsetWidth/document.fonts) reports the host's installed fonts, the \
             scrollbar width is the host toolkit's, canvas/audio render on the host stack, and \
             the WebGL DEEP PARAMETERS (getSupportedExtensions + MAX_* limits) are the host GL \
             driver's even though the renderer/vendor STRINGS are persona-coherent, a detector \
             cross-referencing the ANGLE/Direct3D renderer against the limits sees the mismatch. \
             navigator.gpu (WebGPU) presence is also HOST/engine-conditional, absent on a Linux \
             host, so a Windows/Mac persona lacks it though the real target OS (WebGPU default-on) \
             has it; it is not soundly JS-spoofable (a large async API). \
             The stock JS path cannot soundly spoof rendered surfaces nor the WebGL parameter set \
             (a pixel/layout/getExtension/allocation oracle disproves faked values). The \
             JS-readable surfaces (UA/platform/oscpu/timezone/WebGL renderer+vendor \
             strings/hardwareConcurrency) ARE coherent. reynard helps at the engine level (font \
             WHITELIST + GL strings/params, and it DOES farble audio + perturb the text-canvas via \
             glyph spacing in every realm for per-identity UNLINKABILITY) but does NOT fix cross-OS \
             MIMICRY: it does not re-render the target OS's glyph outlines/metrics, so a reynard \
             Windows persona's text canvas is host glyphs + per-identity noise (matching no real \
             Windows machine) and font enumeration still shows host fonts. Match the persona to the \
             host OS for fully coherent rendered surfaces.",
            overrides.platform,
            std::env::consts::OS
        );
    }
}

#[cfg(test)]
mod cross_os_rendering_tell_tests {
    use super::cross_os_rendering_mismatch;

    #[test]
    fn windows_or_mac_persona_on_linux_host_is_a_mismatch() {
        assert!(cross_os_rendering_mismatch("Win32", "linux"));
        assert!(cross_os_rendering_mismatch("Win64", "linux"));
        assert!(cross_os_rendering_mismatch("MacIntel", "linux"));
    }

    #[test]
    fn matched_persona_and_host_is_not_a_mismatch() {
        assert!(!cross_os_rendering_mismatch("Linux x86_64", "linux"));
        assert!(!cross_os_rendering_mismatch("Win32", "windows"));
        assert!(!cross_os_rendering_mismatch("MacIntel", "macos"));
    }

    #[test]
    fn unrecognized_persona_platform_makes_no_claim() {
        // A platform we cannot classify must not assert a mismatch (no false tell).
        assert!(!cross_os_rendering_mismatch("SomethingExotic", "linux"));
        assert!(!cross_os_rendering_mismatch("", "linux"));
    }

    #[test]
    fn linux_persona_on_windows_or_mac_host_is_a_mismatch() {
        // Symmetric: a Linux persona on a non-Linux host leaks too.
        assert!(cross_os_rendering_mismatch("Linux x86_64", "windows"));
        assert!(cross_os_rendering_mismatch("Linux x86_64", "macos"));
    }
}

#[cfg(test)]
mod apply_path_law10_audit {
    //! G262 / Law 10, the JS + fingerprint apply path must SURFACE every
    //! evaluate / preload-registration / fingerprint-apply failure, never
    //! bind-and-discard or otherwise swallow it. A swallowed apply error is
    //! exactly how the entire stealth layer once became a no-op while every
    //! caller still saw `Ok(page)`: a half-stealthed page (canvas/audio/WebGL
    //! evasion silently absent) is a top-weighted fingerprint tell that ships
    //! invisibly. This guard is the regression fence for the inject.rs / mod.rs
    //! fixes that turned `let _ = page.evaluate(...)` / `let _ = apply_fingerprint(...)`
    //! into `...await.map_err(...)?`.
    //!
    //! It walks the real apply-path source (`src/browser`, `src/fingerprint`)
    //! and fails if any non-comment line both calls a Page apply/eval/preload
    //! method AND carries a result-swallowing token. Directory-walking, so it
    //! auto-covers new files in either tree.
    //!
    //! Self-immunity: every token below is assembled with `concat!` so the
    //! joined literal never appears in this audit file (otherwise the guard
    //! would flag itself); pure-comment lines are skipped because the apply
    //! path's own doc comments quote the banned tokens in prose.
    use std::fs;
    use std::path::{Path, PathBuf};

    fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }

    fn is_full_line_comment(line: &str) -> bool {
        line.trim_start().starts_with("//")
    }

    #[test]
    fn apply_path_never_swallows_an_evaluate_or_apply() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rs_files(&root.join("src/browser"), &mut files);
        rs_files(&root.join("src/fingerprint"), &mut files);
        assert!(
            files.len() >= 4,
            "apply-path audit found only {} files, the walk is mis-rooted; it must \
             cover the browser + fingerprint apply trees",
            files.len()
        );

        // Page apply/eval/preload entry points whose failure MUST surface.
        let method_tokens = [
            concat!(".eval", "uate("),
            concat!(".add_preload", "_script("),
            concat!("apply_finger", "print("),
            concat!("apply_steal", "th"),
        ];
        // Result-swallowing constructs banned on those lines.
        let swallow_tokens = [
            concat!("let _", " ="),
            concat!(".ok", "()"),
            concat!("unwrap", "_or"),
            concat!("Err(_)", " =>"),
        ];

        let mut scanned_method_lines = 0usize;
        for f in &files {
            let Ok(src) = fs::read_to_string(f) else {
                continue;
            };
            for (idx, line) in src.lines().enumerate() {
                if is_full_line_comment(line) {
                    continue;
                }
                if !method_tokens.iter().any(|t| line.contains(t)) {
                    continue;
                }
                scanned_method_lines += 1;
                if let Some(swallow) = swallow_tokens.iter().find(|t| line.contains(*t)) {
                    panic!(
                        "{}:{}: a Page apply/evaluate call is paired with the result-swallowing \
                         token {swallow:?} (Law 10 / G262). A swallowed stealth-apply error ships a \
                         half-stealthed page while the caller sees success. Surface it with \
                         `.map_err(...)?`, never bind-and-discard. Line: {}",
                        f.display(),
                        idx + 1,
                        line.trim()
                    );
                }
            }
        }
        // The audit is only meaningful if it actually exercised the apply calls;
        // a zero count means the method tokens drifted from the real source.
        assert!(
            scanned_method_lines >= 3,
            "apply-path audit matched only {scanned_method_lines} apply/eval call sites, the \
             method tokens have drifted from the real apply path and the guard is now inert"
        );
    }
}

#[cfg(test)]
mod persona_gate_wiring_audit {
    //! X007 / X045 wiring fence: every persona-launch entry point MUST invoke the
    //! unified coherence gate (`persona_full_stack_coherence`) before launching, so
    //! an incoherent persona fails LOUD instead of launching a detectable browser.
    //!
    //! The gate's *behavior* is proven elsewhere, it rejects a broken persona via
    //! the `full_stack_coherence_of` seam (`session_coherence::tests`), and every
    //! shipped persona passes (`every_persona_passes_full_stack_coherence`). What
    //! those cannot prove is that LAUNCH actually calls it: `StealthProfile` is an
    //! enum of only-coherent variants, so no behavioral test can pass an incoherent
    //! persona through `launch_*`. This source-walk is the regression fence for the
    //! wiring itself (it fails if a future edit drops the gate from a launch path).
    //!
    //! Self-immunity: the gate token is assembled with `concat!` so the joined
    //! literal never appears in this audit's own source (else it would match
    //! itself); pure-comment lines are skipped so the doc prose above doesn't count.
    use std::fs;
    use std::path::Path;

    #[test]
    fn every_persona_launch_entrypoint_invokes_the_coherence_gate() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let enforce = concat!("enforce_persona_launch", "_coherence(");
        let gate = concat!("persona_full_stack", "_coherence(");

        // The wiring contract after centralisation: every persona-launch entry
        // point calls the shared primitive, and the primitive calls the hard gate.
        // `(file, fn whose BODY must contain `needed`, needed token, what it proves)`.
        let checks: [(&str, &str, &str, &str); 3] = [
            (
                "src/browser/mod.rs",
                concat!("fn launch_profiled", "_firefox("),
                enforce,
                "launch_profiled_firefox must call the shared enforcement primitive",
            ),
            (
                "src/browser/reynard.rs",
                concat!("fn launch_reynard", "_with_config("),
                enforce,
                "launch_reynard_with_config must call the shared enforcement primitive",
            ),
            (
                "src/browser/mod.rs",
                concat!("fn enforce_persona_launch", "_coherence("),
                gate,
                "the enforcement primitive must call the hard coherence gate",
            ),
        ];

        for (rel, fn_sig, needed, proves) in checks {
            let src = fs::read_to_string(root.join(rel))
                .unwrap_or_else(|e| panic!("cannot read {rel} for the wiring audit: {e}"));
            let start = src.find(fn_sig).unwrap_or_else(|| {
                panic!("{rel}: fn signature {fn_sig:?} not found, the wiring audit is mis-targeted")
            });
            // Body = from the signature to the next top-level `pub ` item (or EOF):
            // enough to scope the call to THIS function, not a neighbour.
            let after = &src[start + fn_sig.len()..];
            let end = after
                .find("\npub ")
                .map_or(src.len(), |off| start + fn_sig.len() + off);
            let body = &src[start..end];
            assert!(
                body.contains(needed),
                "{rel}: {proves}: {needed} not found in the body of {fn_sig}. A launch \
                 boundary is UNWIRED; an incoherent persona could launch undetected."
            );
        }
    }
}

#[cfg(test)]
mod reynard_js_spoof_separation_audit {
    //! G076-G079 / R146 separation-of-layers fence.
    //!
    //! The reynard path handles fingerprint surfaces inside the engine, so it must
    //! NOT invoke the JS stealth / fingerprint layers. The stock-Firefox path has
    //! no engine-level spoofing for canvas, audio, fonts, or WebGL, so it MUST
    //! invoke those JS layers. Because both launchers accept the same `StealthProfile`
    //! type, only a source audit can prove the separation; this test is that fence.
    use std::fs;
    use std::path::Path;

    #[test]
    fn reynard_launcher_does_not_call_js_spoof_layers() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let src = fs::read_to_string(root.join("src/browser/reynard.rs"))
            .expect("reynard source must be readable");
        let start = src
            .find(concat!("fn launch_reynard", "_with_config("))
            .expect("launch_reynard_with_config must exist");
        let after = &src[start..];
        let end = after.find("\npub ").map_or(src.len(), |off| start + off);
        let body = &src[start..end];

        let forbidden = [
            concat!("apply_steal", "th_profile"),
            concat!("apply_steal", "th_profile_with_overrides"),
            concat!("apply_finger", "print("),
        ];
        for token in forbidden {
            assert!(
                !body.contains(token),
                "src/browser/reynard.rs: launch_reynard_with_config must NOT call the JS spoof \
                 layer (forbidden token {token:?}). The reynard engine handles these surfaces \
                 natively; adding the JS layer would fight the engine and create coherence tells."
            );
        }
    }

    #[test]
    fn stock_firefox_launcher_calls_js_spoof_layers() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let src = fs::read_to_string(root.join("src/browser/mod.rs"))
            .expect("browser/mod.rs must be readable");
        let start = src
            .find(concat!("fn launch_profiled", "_firefox("))
            .expect("launch_profiled_firefox must exist");
        let after = &src[start..];
        let end = after.find("\npub ").map_or(src.len(), |off| start + off);
        let body = &src[start..end];

        let required = [
            (
                concat!("apply_steal", "th_profile_with_overrides"),
                "the navigator/header/runtime stealth layer",
            ),
            (
                concat!("apply_finger", "print("),
                "the canvas/audio/font/WebGL fingerprint evasion layer",
            ),
        ];
        for (token, what) in required {
            assert!(
                body.contains(token),
                "src/browser/mod.rs: launch_profiled_firefox must call {what} ({token:?}). \
                 Stock Firefox has no native spoofing for these surfaces; omitting the JS layer \
                 would ship a detectable browser."
            );
        }
    }
}

#[cfg(test)]
mod browser_launch_profile_gate {
    //! G092 launch-path guard: a Chromium/Safari/IE persona must not be launched
    //! on the Firefox engine. These tests drive the PURE gate predicate
    //! ([`super::firefox_engine_family_gate`]) directly, so they spawn no browser
    //! and are deterministic on any host, the gate is what we are asserting, not a
    //! real launch (which would actually start Firefox where one is on PATH and
    //! flake under parallel load).
    use super::firefox_engine_family_gate;
    use crate::StealthProfile;

    fn rejected_by_engine_gate(profile: &StealthProfile) -> bool {
        match firefox_engine_family_gate(profile) {
            Ok(()) => false,
            Err(e) => format!("{e}").contains("cannot be launched on a Firefox engine"),
        }
    }

    #[test]
    fn firefox_profile_passes_engine_gate() {
        assert!(
            firefox_engine_family_gate(&StealthProfile::FirefoxLinux).is_ok(),
            "FirefoxLinux must pass the Firefox engine-family gate"
        );
        assert!(!rejected_by_engine_gate(&StealthProfile::FirefoxLinux));
    }

    #[test]
    fn chrome_profile_is_refused_by_firefox_engine_gate() {
        assert!(
            rejected_by_engine_gate(&StealthProfile::ChromeWindowsStable),
            "Chromium profile must be refused by the Firefox engine-family gate"
        );
    }

    #[test]
    fn safari_profile_is_refused_by_firefox_engine_gate() {
        assert!(
            rejected_by_engine_gate(&StealthProfile::SafariMacStable),
            "Safari profile must be refused by the Firefox engine-family gate"
        );
    }

    #[test]
    fn firefox_mac_profile_passes_engine_gate() {
        // Positive twin for the macOS Firefox persona: same-family must pass.
        assert!(
            firefox_engine_family_gate(&StealthProfile::FirefoxMacStable).is_ok(),
            "FirefoxMacStable must pass the Firefox engine-family gate"
        );
        assert!(!rejected_by_engine_gate(&StealthProfile::FirefoxMacStable));
    }
}
