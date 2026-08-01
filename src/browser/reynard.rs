//! guise → **reynard** engine-config bridge.
//!
//! `reynard` (our Camoufox fork, see project notes) spoofs fingerprints in
//! patched Gecko C++ rather than via injected JS. It reads one JSON config blob
//! from an environment variable at startup ([`REYNARD_CONFIG_ENV`]) and applies
//! every surface natively, so there is nothing for a page to `toString`-probe.
//!
//! This module maps guise's pure-data [`crate::ProfileOverrides`] onto that
//! config's key schema (`additions/camoucfg` `properties.json`), so the SAME
//! persona that drives the JS disguise also drives the engine, one source of
//! truth, two backends.
//!
//! The native-passthrough rule from the JS path carries over verbatim: when a
//! matched-host persona leaves `webgl_vendor`/`webgl_renderer` empty, the WebGL
//! keys are OMITTED so reynard exposes the host's real, self-consistent adapter
//! (whose pixels match) instead of a constant, see the WebGL note on
//! `FIREFOX_STEALTH_BODY`.

use crate::ProfileOverrides;
use runtime_foxdriver::browser::{launch_firefox_self_managed, FoxBrowserConfig, Page};
use serde_json::{json, Map, Value};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-launch counter so concurrent launches get unique temp dirs.
static LAUNCH_SEQ: AtomicU64 = AtomicU64::new(0);

/// Environment variable reynard's patched Gecko reads its JSON config from.
///
/// The reynard fork's name. `MaskConfig.hpp` reads `REYNARD_CONFIG[_<n>]` first
/// and falls back to the upstream `CAMOU_CONFIG[_<n>]`, so this const and the
/// engine stay in lockstep while remaining compatible with any older binary.
pub const REYNARD_CONFIG_ENV: &str = "REYNARD_CONFIG";

/// Maximum bytes per env var before chunking into `REYNARD_CONFIG_1..N`.
/// Generous headroom under typical `ARG_MAX`/env limits; the engine concatenates
/// the numbered parts in order before parsing.
const ENV_CHUNK_BYTES: usize = 100_000;

/// Build the reynard engine config object from a persona.
///
/// Surfaces spoofed natively by the reynard engine (this function sets only the
/// keys guise owns):
///   - navigator: userAgent, webdriver, platform, hardwareConcurrency, language(s),
///     maxTouchPoints
///   - screen / window geometry: width, height, colorDepth, pixelDepth, avail*,
///     screenX/Y, outerWidth/Height, innerWidth/Height (coherent chrome band)
///   - fonts: system whitelist restricted to standard Linux families
///   - WebGL vendor/renderer when the persona carries one
///   - HTTP headers: User-Agent, Accept-Language (engine-emitted, not JS)
///
/// These are intentionally handled by the engine rather than `profile_js` / the
/// guise fingerprint evasion layer. The reynard path therefore does NOT call
/// `apply_stealth_profile` or `apply_fingerprint`; injecting the JS layer would
/// fight the engine's own patches and re-introduce coherence tells.
///
/// DEVICE-NOISE SEEDS are NOT set here: `reynard_config` is the pure persona map;
/// the per-identity `audio:seed` / `fonts:spacing_seed` / `canvas:seed` are added by
/// [`launch_reynard_with_config`] (it owns the profile_dir → seed derivation). What
/// each does on the reynard ENGINE, verified live
/// (tests/reynard_canvas_audio_farble_live.rs):
///   * `audio:seed` → `AudioFingerprintManager` farbles the audio fingerprint. Audio
///     FP is a WINDOW-only surface (Firefox exposes no `OfflineAudioContext` in a
///     Worker), so window coverage is total coverage.
///   * `fonts:spacing_seed` → `FontSpacingSeedManager` perturbs glyph spacing, which
///     shifts any TEXT-based canvas fingerprint, and it reaches EVERY realm
///     (window == worker confirmed), the engine-level coverage the stock-FF JS preload
///     cannot give a Worker's OffscreenCanvas.
///   * `canvas:seed` → INERT: NO reader exists in the reynard tree, so pure-SHAPE
///     (non-text) 2D-canvas pixels are NOT noised. Set for forward-compat (a future
///     engine canvas manager would activate it with no wiring change).
///
/// So with a seed the reynard canvas/audio FP DIFFERS from the bare host and is
/// realm-coherent; WITHOUT one (ephemeral) it is the real host FP. (`fonts`/`webGl`/
/// navigator/screen ARE engine-spoofed by the keys below.)
#[must_use]
pub fn reynard_config(overrides: &ProfileOverrides) -> Value {
    let mut cfg = Map::new();

    // ── navigator ───────────────────────────────────────────────────────────
    cfg.insert("navigator.userAgent".into(), json!(overrides.user_agent));
    // Driven over BiDi, the engine's Navigator::Webdriver() otherwise returns
    // true (remote agent active), the sannysoft "WebDriver" tell. The reynard
    // engine patch honors this REYNARD_CONFIG key; pin it false for every persona.
    cfg.insert("navigator.webdriver".into(), json!(false));
    cfg.insert("navigator.platform".into(), json!(overrides.platform));
    cfg.insert(
        "navigator.hardwareConcurrency".into(),
        json!(overrides.hardware_concurrency),
    );
    if let Some(primary) = overrides.languages.first() {
        cfg.insert("navigator.language".into(), json!(primary));
    }
    if !overrides.languages.is_empty() {
        cfg.insert("navigator.languages".into(), json!(overrides.languages));
        // The engine's browser-init derives `intl.accept_languages`: which is what
        // populates the `navigator.languages` array, from `locale:all` first, and
        // only falls back to the single `navigator.language` otherwise. Without
        // `locale:all` the array collapses to the primary alone (`["en-US"]`,
        // length 1), a coherence tell the differential oracle flags against a real
        // FF-Linux en-US (`["en-US","en"]`). Emit the full list in the comma-space
        // form Firefox uses for the pref so the derived array matches exactly.
        cfg.insert("locale:all".into(), json!(overrides.languages.join(", ")));
    }
    cfg.insert(
        "navigator.maxTouchPoints".into(),
        json!(if overrides.mobile { 5 } else { 0 }),
    );

    // ── screen ──────────────────────────────────────────────────────────────
    cfg.insert("screen.width".into(), json!(overrides.screen_width));
    cfg.insert("screen.height".into(), json!(overrides.screen_height));
    cfg.insert("screen.colorDepth".into(), json!(overrides.color_depth));
    cfg.insert("screen.pixelDepth".into(), json!(overrides.color_depth));
    // ── window / available-screen geometry coherence ─────────────────────────
    // The engine spoofs `screen.width/height` but NOT, by default, the available
    // area or the window box, so it leaks the HOST display via `screen.avail*`
    // (e.g. avail 3840x2160 while screen claims 1920x1080) AND opens a headful
    // window sized for the real monitor, taller than the spoofed screen. Both are
    // the incolumitas `PHANTOM_WINDOW_HEIGHT` class of tell (`outerHeight >
    // screen.height`, window off-screen), proven by `tests/reynard_window_geometry`
    // against a real Firefox baseline. Pin a coherent MAXIMIZED window on the
    // persona's screen: a Linux desktop reserves no persistent taskbar (avail ==
    // screen, matching a real FF-Linux capture), the frame fills the screen at the
    // origin, and the content area sits below a realistic toolbar/tab/bookmarks
    // band. The 124px band is tuned so the spoofed `innerHeight` equals the engine's
    // ACTUAL rendered viewport (visualViewport / documentElement.clientHeight), a
    // larger band left `window.innerHeight` reporting ~36px more than the real
    // layout, itself a softer tell; `tests/reynard_window_geometry` pins the match.
    const CHROME_BAND: u32 = 124;
    cfg.insert("screen.availLeft".into(), json!(0));
    cfg.insert("screen.availTop".into(), json!(0));
    cfg.insert("screen.availWidth".into(), json!(overrides.screen_width));
    cfg.insert("screen.availHeight".into(), json!(overrides.screen_height));
    cfg.insert("window.screenX".into(), json!(0));
    cfg.insert("window.screenY".into(), json!(0));
    cfg.insert("window.outerWidth".into(), json!(overrides.screen_width));
    cfg.insert("window.outerHeight".into(), json!(overrides.screen_height));
    cfg.insert("window.innerWidth".into(), json!(overrides.screen_width));
    // Desktop carries a toolbar/tab band; a mobile persona is chromeless fullscreen
    // (outer == inner == screen), so subtracting a desktop chrome band there would
    // itself be the tell. Verified for desktop by `reynard_window_geometry`.
    let inner_height = if overrides.mobile {
        overrides.screen_height
    } else {
        overrides.screen_height.saturating_sub(CHROME_BAND)
    };
    cfg.insert("window.innerHeight".into(), json!(inner_height));

    // ── fonts, restrict the visible set to a common standard-Linux list. The
    //    engine maps this to font.system.whitelist, so font-list fingerprinting
    //    sees a small coherent set instead of the host's identifying ~300-family
    //    install (which leaked CJK/extra families). Every family below ships on
    //    typical Linux desktops, so the engine's measureText enumeration stays
    //    coherent. Linux persona only (cross-OS personas need their own list). ──
    if overrides.platform.contains("Linux") {
        cfg.insert(
            "fonts".into(),
            json!(crate::fingerprint::font_tier_b::LINUX_STANDARD_FONTS),
        );
    }

    // ── WebGL, native passthrough: only pin when the persona explicitly
    //    carries a (cross-OS) adapter. Empty = expose the real one. ──
    if !overrides.webgl_vendor.is_empty() {
        cfg.insert("webGl:vendor".into(), json!(overrides.webgl_vendor));
    }
    if !overrides.webgl_renderer.is_empty() {
        cfg.insert("webGl:renderer".into(), json!(overrides.webgl_renderer));
    }

    // ── HTTP header coherence (engine emits these so the network layer matches
    //    the JS surface) ──
    cfg.insert("headers.User-Agent".into(), json!(overrides.user_agent));
    if !overrides.languages.is_empty() {
        cfg.insert(
            "headers.Accept-Language".into(),
            json!(accept_language(&overrides.languages)),
        );
    }

    Value::Object(cfg)
}

/// Render the persona as the `(env_name, value)` pairs to set on the reynard
/// process. Returns chunked `REYNARD_CONFIG_1..N` pairs when the JSON exceeds
/// [`ENV_CHUNK_BYTES`], else a single [`REYNARD_CONFIG_ENV`] pair.
#[must_use]
pub fn reynard_config_env(overrides: &ProfileOverrides) -> Vec<(String, String)> {
    let blob = reynard_config(overrides).to_string();
    if blob.len() <= ENV_CHUNK_BYTES {
        return vec![(REYNARD_CONFIG_ENV.to_string(), blob)];
    }
    blob.as_bytes()
        .chunks(ENV_CHUNK_BYTES)
        .enumerate()
        .map(|(i, part)| {
            (
                format!("{REYNARD_CONFIG_ENV}_{}", i + 1),
                String::from_utf8_lossy(part).into_owned(),
            )
        })
        .collect()
}

/// Build an `Accept-Language` header value from a language list
/// (`en-US,en;q=0.9,fr;q=0.8` style) so it coheres with `navigator.languages`.
fn accept_language(langs: &[String]) -> String {
    langs
        .iter()
        .enumerate()
        .map(|(i, lang)| {
            if i == 0 {
                lang.clone()
            } else {
                // q drops 0.1 per position, floored at 0.1.
                let q = (10 - i.min(9)) as f64 / 10.0;
                format!("{lang};q={q}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The wrapper shell script that injects the persona config and execs the real
/// reynard binary. Pure (no IO) so the shell logic is unit-testable.
///
/// rustenium spawns the browser binary directly and exposes no per-child env
/// hook, so we front `reynard_bin` with this wrapper: it loads `REYNARD_CONFIG`
/// from `cfg_path` (a file, so any JSON byte survives shell quoting) and forwards
/// rustenium's BiDi launch flags to the binary via `"$@"`. Per-launch and
/// concurrency-safe, no process-global env, no `unsafe` set_var (guise forbids
/// unsafe).
fn reynard_wrapper_script(cfg_path: &str, reynard_bin: &str) -> String {
    // Use the REYNARD_CONFIG_ENV const so the launch path and the engine's
    // MaskConfig env name stay in lockstep across the camoufox->reynard rename.
    format!(
        "#!/bin/sh\n\
         # guise -> reynard launch wrapper (per-launch {env}, no global env)\n\
         {env}=\"$(cat '{cfg_path}')\"\n\
         export {env}\n\
         exec '{reynard_bin}' \"$@\"\n",
        env = REYNARD_CONFIG_ENV,
    )
}

/// A Firefox-family binary's **major** version, parsed from `<bin> --version`
/// (`"Mozilla Camoufox 150.0.2-beta.25"` → `150`; `"Mozilla Firefox 151.0.3"` →
/// `151`). Works for the reynard engine binary AND a stock Firefox.
///
/// A real Firefox build's TLS (JA3/JA4) and version-gated JS features are the
/// engine's actual version. The persona UA, by contrast, is pinned to whatever
/// the TLS-impersonate **HTTP-client** profile ships, a different path. Both
/// the reynard launch and the stock-Firefox profiled launch align the persona UA
/// to this engine major so navigator.userAgent claims the version the engine
/// truly is. Returns `None` (caller keeps the persona UA) if `--version` can't
/// run.
#[must_use]
pub fn firefox_engine_major(bin: &str) -> Option<u32> {
    let out = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // First whitespace token that looks like a dotted version (e.g. "150.0.2").
    text.split_whitespace()
        .find(|t| t.contains('.') && t.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .and_then(|t| t.split('.').next())
        .and_then(|n| n.parse::<u32>().ok())
}

/// Rewrite the Firefox **major** version in a UA string to `engine_major`,
/// preserving structure (only `rv:<n>.` and `Firefox/<n>.` change). A no-op when
/// the persona already matches or no Firefox token is present.
#[must_use]
pub fn align_ua_to_engine(ua: &str, engine_major: u32) -> String {
    let persona_major = ua
        .rsplit("Firefox/")
        .next()
        .filter(|_| ua.contains("Firefox/"))
        .and_then(|s| s.split('.').next())
        .and_then(|s| s.parse::<u32>().ok());
    match persona_major {
        Some(p) if p != engine_major => ua
            .replace(&format!("rv:{p}."), &format!("rv:{engine_major}."))
            .replace(
                &format!("Firefox/{p}."),
                &format!("Firefox/{engine_major}."),
            ),
        _ => ua.to_string(),
    }
}

/// Stable 64-bit seed from an account key (its `profile_dir`), so per-identity
/// canvas/audio/font noise is deterministic per account, identical across that
/// account's sessions, different across accounts. FNV-1a: no deps, well spread.
#[must_use]
pub fn identity_seed(key: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Resolve a reynard (stealth-engine) binary path, or `None` to fall back to a
/// plain Firefox on PATH. Every launch path that wants stealth, captchaforge's
/// `drive_browser`, the guise-bridge, Meridian, should call this and set
/// [`runtime_foxdriver::browser::FoxBrowserConfig::executable_path`] to the result.
///
/// Resolution order (first non-empty / existing wins):
/// 1. `REYNARD_BIN` env (the direct override the gate tests + tooling set).
/// 2. `GUISE_REYNARD_BIN` env (the name the guise-bridge / Meridian launcher uses).
/// 3. Conventional install locations `scripts/install-reynard.sh` symlinks to
///    (`~/.local/share/reynard/reynard`, `~/.cache/reynard/reynard`,
///    `/opt/reynard/reynard`), so a built reynard is the DEFAULT engine however the
///    caller was started.
///
/// Both env names are honored because both are already in fleet use (tests set the
/// former, the bridge the latter) (one resolver, one convention).
///
/// A `None` result means the launch will use plain Firefox, which leaks
/// `navigator.webdriver = true` over BiDi, detectable. Callers MUST surface that
/// fallback LOUDLY (Law 10): a stealth tool silently driving a detectable browser
/// is a recall bug, not a graceful default.
#[must_use]
pub fn resolve_reynard_bin() -> Option<String> {
    resolve_reynard_bin_from(
        |k| std::env::var(k).ok(),
        |p| std::path::Path::new(p).exists(),
    )
}

/// Testable seam for [`resolve_reynard_bin`]: the env lookup and path-existence
/// check are injected so the resolution order (env names first, then the
/// conventional install paths) is unit-tested deterministically, no process
/// environment or filesystem dependence.
fn resolve_reynard_bin_from(
    env: impl Fn(&str) -> Option<String>,
    exists: impl Fn(&str) -> bool,
) -> Option<String> {
    for var in ["REYNARD_BIN", "GUISE_REYNARD_BIN"] {
        if let Some(s) = env(var) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    let home = env("HOME").unwrap_or_default();
    [
        format!("{home}/.local/share/reynard/reynard"),
        format!("{home}/.cache/reynard/reynard"),
        "/opt/reynard/reynard".to_string(),
    ]
    .into_iter()
    .find(|p| exists(p))
}

/// Launch the reynard engine binary, driven over BiDi, with `profile`'s
/// fingerprint applied **natively** via `REYNARD_CONFIG` (no JS injection).
///
/// Each call writes its own config + wrapper to a unique temp dir, so concurrent
/// launches with different personas never collide. Run `headless = false` on a
/// real-GPU display for zero headless tells; reynard's pointer/headless patches
/// also keep headless coherent if you must use it.
///
/// The returned [`Page`] is the same handle the JS-disguise path returns, so the
/// differential oracle ([`crate::probe::diff_pages`]) can diff a reynard page
/// against a stock-Firefox page directly, the "patched vs stock = identical"
/// gate.
pub async fn launch_reynard(
    reynard_bin: &str,
    profile: &crate::StealthProfile,
    headless: bool,
) -> anyhow::Result<Page> {
    launch_reynard_with_config(
        reynard_bin,
        profile,
        FoxBrowserConfig {
            headless,
            viewport_width: 1280,
            viewport_height: 720,
            ..Default::default()
        },
    )
    .await
}

/// Launch the reynard engine, MERGING the per-launch wrapper into a
/// caller-supplied [`FoxBrowserConfig`] so the caller's proxy, profile dir,
/// viewport, and any extra prefs are preserved.
///
/// This is the integration point for long-lived drivers (e.g. the guise bridge
/// that Meridian talks to): they build a `FoxBrowserConfig` with the session's
/// `profile_dir` + residential `proxy`, and reynard adds only the engine
/// wrapper (`executable_path` → the REYNARD_CONFIG-exporting launcher) and the
/// `navigator.webdriver` pref. `config.executable_path` is overridden; the
/// reynard pref is appended to any existing `user_js_content`; `config.proxy`
/// and `config.profile_dir` flow through to `launch_firefox_self_managed`
/// (which still appends the proxy prefs), so residential egress + session
/// persistence are unchanged versus the plain-Firefox path.
pub async fn launch_reynard_with_config(
    reynard_bin: &str,
    profile: &crate::StealthProfile,
    mut config: FoxBrowserConfig,
) -> anyhow::Result<Page> {
    // X007 / X045, enforce the unified persona coherence contract at the reynard
    // launch boundary too, via the SAME shared primitive the stock-Firefox path uses.
    // reynard drives a REAL Gecko engine, but the persona it wears must still be
    // self-consistent JS-to-wire; a malformed persona is just as detectable behind
    // reynard. `config.proxy` flows through to the engine, so a configured proxy
    // correctly suppresses the host-TTL warning.
    super::enforce_persona_launch_coherence(profile, config.proxy.is_none())?;

    let mut overrides = crate::profile_to_overrides(profile);
    // Align the persona UA to the ACTUAL reynard engine version. The persona's
    // own UA major tracks the TLS-impersonate HTTP profile (a different,
    // HTTP-client path); the reynard BROWSER uses real Gecko TLS + features, so
    // claiming the engine's true version keeps navigator.userAgent coherent with
    // JA3/JA4 and version-gated JS. No-op if `--version` is unreadable.
    if let Some(major) = firefox_engine_major(reynard_bin) {
        overrides.user_agent = align_ua_to_engine(&overrides.user_agent, major);
    }
    // Per-identity device noise seed. ALWAYS set, mirroring the stock-FF path:
    //   * profile_dir persona → STABLE seed from the dir, so the account reads as the
    //     SAME device across its own sessions but DIFFERENT from other accounts
    //     (defeating the serial-signup correlation an anti-bot blocks on).
    //   * ephemeral persona (no profile_dir) → RANDOM per-launch seed, so repeated
    //     ephemeral launches from one host are NOT linkable by audio/canvas FP. Before
    //     this, ephemeral left the seeds UNSET and leaked the stable REAL-host audio +
    //     text-canvas FP (confirmed live, tests/reynard_canvas_audio_farble_live.rs:
    //     no-pdir == bare host), a parity gap vs the stock-FF path, which already
    //     random-seeds an ephemeral persona.
    // Effect of each seed on the engine (verified, same test):
    //   * audio:seed → AudioFingerprintManager farbles the (window-only) audio FP.
    //   * fonts:spacing_seed → FontSpacingSeedManager shifts TEXT-canvas FP in EVERY
    //     realm (window == worker) (engine-level worker coverage the JS path lacks).
    //   * canvas:seed → INERT (no engine reader); set for forward-compat only.
    // Safe for reynard_gate: its canvas/audio probes are Medium-severity STABILITY/shape
    // checks (farble-invariant), and the gate asserts only on High-severity divergence.
    let mut cfg = reynard_config(&overrides);
    if let Value::Object(map) = &mut cfg {
        let seed = match config.profile_dir.as_deref().filter(|d| !d.is_empty()) {
            Some(dir_key) => identity_seed(dir_key) % 1_000_000,
            None => u64::from(rand::random::<u32>()) % 1_000_000,
        };
        map.insert("canvas:seed".into(), json!(seed));
        map.insert("audio:seed".into(), json!(seed));
        map.insert("fonts:spacing_seed".into(), json!(seed));
        // NB: WebRTC IP masking is NOT a config key (the engine reads it only
        // via the content-callable window.setWebRTCIPv4); the guise-bridge
        // applies it per-launch from the same identity_seed.
    }
    let config_json = cfg.to_string();

    let seq = LAUNCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("reynard-launch-{}-{}", std::process::id(), seq));
    std::fs::create_dir_all(&dir)
        .map_err(|e| anyhow::anyhow!("create reynard launch dir {dir:?}: {e}"))?;

    let cfg_path = dir.join("config.json");
    std::fs::write(&cfg_path, &config_json)
        .map_err(|e| anyhow::anyhow!("write reynard config: {e}"))?;

    let wrapper_path = dir.join("launch.sh");
    let script = reynard_wrapper_script(&cfg_path.to_string_lossy(), reynard_bin);
    std::fs::write(&wrapper_path, script)
        .map_err(|e| anyhow::anyhow!("write reynard wrapper: {e}"))?;
    let mut perms = std::fs::metadata(&wrapper_path)
        .map_err(|e| anyhow::anyhow!("stat reynard wrapper: {e}"))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&wrapper_path, perms)
        .map_err(|e| anyhow::anyhow!("chmod reynard wrapper: {e}"))?;

    // Timezone: pin the persona's IANA zone as a per-process `TZ` env var on the
    // engine process (the same mechanism the stock-Firefox path uses). ICU reads TZ
    // in EVERY realm, so window AND dedicated-Worker `Intl`/`Date` report the
    // persona zone, DST-correct. Without it reynard inherited the HOST zone in both
    // realms (verified live, `tests/reynard_session_tells.rs`: a FirefoxLinux
    // persona reported `America/Phoenix`: the host, not the persona's
    // `America/New_York`), leaking the host machine's location and correlating
    // every identity launched from one host. The wrapper `exec`s the engine, so the
    // env set on the wrapper process is inherited by reynard. Per-process, so
    // concurrent launches with different personas never race. The operator can
    // realign `overrides.timezone` to a proxy's egress geography via
    // `ProfileOverrides::with_timezone` before launch.
    config
        .env
        .push(("TZ".to_string(), overrides.timezone.clone()));

    // The engine wrapper replaces the executable; everything else the caller set
    // (proxy, profile_dir, viewport, headless) is preserved.
    config.executable_path = Some(wrapper_path.to_string_lossy().into_owned());
    // `navigator.webdriver` is set true by the BiDi remote agent; disable the
    // pref at the PROFILE layer so the getter reads false WITHOUT a JS override
    // that `.toString()` could leak. (`remote.enabled` is deliberately NOT
    // touched: BiDi needs it to connect.) Append rather than replace so a
    // caller's prefs survive; foxdriver still appends `config.proxy` prefs.
    config.user_js_content = Some(merge_reynard_prefs(config.user_js_content.take()));

    // G126 / R148: capture the identity key before `config` is consumed by
    // launch, so session-age seeding can reuse the same stable seed that drives
    // canvas/audio/font noise.
    let age_key: String = config
        .profile_dir
        .as_deref()
        .filter(|d| !d.is_empty())
        .unwrap_or("guise-default-session-age")
        .to_string();

    // Self-managed launch: foxdriver spawns the wrapper (which exports
    // REYNARD_CONFIG then execs the engine) and polls the debug port until it is
    // live before attaching. A freshly-built Camoufox binds its BiDi port in
    // ~1 s, past rustenium's fixed 500 ms post-spawn sleep, so the default
    // managed launch races to a ConnectionRefused; the readiness poll fixes it.
    let page = launch_firefox_self_managed(config).await?;

    // Seed a plausible session age so a fresh profile does not broadcast
    // `history.length == 0` and an empty localStorage.
    let session_age = crate::browser::generate_session_age(identity_seed(&age_key) % 1_000_000);
    crate::browser::apply_session_age(&page, &session_age)
        .await
        .map_err(|e| anyhow::anyhow!("launch_reynard_with_config: apply session age: {e}"))?;

    Ok(page)
}

/// Append [`REYNARD_PROFILE_PREFS`] to any caller-supplied `user.js`, so the
/// `navigator.webdriver` pref is always present without clobbering the caller's
/// prefs. Pure (unit-tested).
fn merge_reynard_prefs(existing: Option<String>) -> String {
    match existing {
        Some(e) if !e.trim().is_empty() => format!("{e}\n{REYNARD_PROFILE_PREFS}"),
        _ => REYNARD_PROFILE_PREFS.to_string(),
    }
}

/// Profile prefs written for every reynard launch. Only automation tells that
/// the engine/REYNARD_CONFIG does not already cover belong here, and nothing that
/// would break the BiDi transport (`remote.enabled` stays on).
///
/// `security.ssl3.ecdhe_ecdsa_aes_128_sha` (cipher 0xc009,
/// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA) is the RUNTIME twin of the
/// `settings/camoufox.cfg` build-time fix: Camoufox's `StaticPrefList.yaml`
/// defaults this single ECDHE-CBC suite to FALSE while every sibling defaults
/// TRUE, so reynard's ClientHello carries 16 ciphers where stock Firefox 150
/// carries 17, a JA3/JA4 cipher-hash + peetprint tell. Setting it here closes
/// the tell on EVERY binary at launch, including a binary built before the
/// camoufox.cfg bake (the current release), so the fix does not wait on a rebuild.
/// Harmless once the rebuild bakes the same default in (defence in depth).
/// Verified == stock FF-150 (17 ciphers) live on tls.peet.ws.
const REYNARD_PROFILE_PREFS: &str = "user_pref(\"dom.webdriver.enabled\", false);\n\
     user_pref(\"security.ssl3.ecdhe_ecdsa_aes_128_sha\", true);";

#[cfg(test)]
#[path = "reynard/tests.rs"]
mod tests;
