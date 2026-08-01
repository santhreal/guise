//! Unit tests for [`super`] (reynard launch prefs, profile merge, and config wiring).

use super::*;
use crate::{profile_to_overrides, StealthProfile};

fn cfg_for(profile: StealthProfile) -> Value {
    reynard_config(&profile_to_overrides(&profile))
}

#[test]
fn maps_navigator_and_screen_from_persona() {
    let ov = profile_to_overrides(&StealthProfile::FirefoxLinux);
    let cfg = reynard_config(&ov);
    assert_eq!(cfg["navigator.userAgent"], json!(ov.user_agent));
    assert_eq!(cfg["navigator.platform"], json!(ov.platform));
    assert_eq!(
        cfg["navigator.hardwareConcurrency"],
        json!(ov.hardware_concurrency)
    );
    assert_eq!(cfg["screen.width"], json!(ov.screen_width));
    assert_eq!(cfg["screen.height"], json!(ov.screen_height));
}

#[test]
fn desktop_window_geometry_is_coherent_with_the_persona_screen() {
    // The PHANTOM_WINDOW_HEIGHT fix: the engine must advertise an available area ==
    // the spoofed screen (no host-display leak via screen.avail*) and a window box
    // that fits WITHIN that screen with a real toolbar/tab band. Live-verified by
    // `tests/reynard_window_geometry`; pinned here so the config can never regress
    // to leaking the host or opening a window taller than its screen.
    let ov = profile_to_overrides(&StealthProfile::FirefoxLinux);
    let cfg = reynard_config(&ov);
    let u = |k: &str| cfg[k].as_u64().unwrap();
    assert_eq!(cfg["screen.availWidth"], json!(ov.screen_width));
    assert_eq!(cfg["screen.availHeight"], json!(ov.screen_height));
    assert_eq!(u("screen.availTop"), 0);
    assert_eq!(u("window.screenX"), 0);
    assert_eq!(u("window.screenY"), 0);
    // The window must NOT be taller than its screen (the phantom tell), and avail
    // must not exceed the screen either.
    assert!(u("window.outerHeight") <= u("screen.height"));
    assert!(u("screen.availHeight") <= u("screen.height"));
    assert!(u("window.screenY") + u("window.outerHeight") <= u("screen.height"));
    // Desktop carries a real chrome band: inner < outer, by the 124px band.
    assert!(u("window.innerHeight") < u("window.outerHeight"));
    assert_eq!(u("window.innerHeight"), u64::from(ov.screen_height) - 124);
}

#[test]
fn mobile_persona_window_is_chromeless_fullscreen() {
    // A mobile persona has no desktop window furniture (outer == inner == screen).
    // Subtracting a desktop chrome band there would be the tell.
    let ov = profile_to_overrides(&StealthProfile::ChromeAndroid);
    assert!(ov.mobile, "ChromeAndroid persona must be mobile");
    let cfg = reynard_config(&ov);
    assert_eq!(cfg["window.innerHeight"], json!(ov.screen_height));
    assert_eq!(cfg["window.outerHeight"], json!(ov.screen_height));
}

#[test]
fn navigator_webdriver_pinned_false_for_every_persona() {
    // The engine patch (Navigator::Webdriver honoring MaskConfig) is only
    // load-bearing if the config actually carries the key (pin it).
    for p in [
        StealthProfile::FirefoxLinux,
        StealthProfile::FirefoxWindows,
        StealthProfile::ChromeWindowsStable,
    ] {
        assert_eq!(cfg_for(p)["navigator.webdriver"], json!(false));
    }
}

#[test]
fn firefox_linux_omits_webgl_keys_for_native_passthrough() {
    // FirefoxLinux is matched-host: empty webgl → keys MUST be absent so the
    // engine exposes the real adapter (mirrors the JS-path decision).
    let cfg = cfg_for(StealthProfile::FirefoxLinux);
    assert!(
        cfg.get("webGl:vendor").is_none(),
        "matched-host persona must not pin a WebGL vendor"
    );
    assert!(cfg.get("webGl:renderer").is_none());
}

#[test]
fn cross_os_persona_pins_webgl() {
    // A persona that carries an explicit adapter (cross-OS) DOES set it.
    let cfg = cfg_for(StealthProfile::ChromeWindowsStable);
    assert!(
        cfg.get("webGl:renderer").is_some(),
        "a persona with a non-empty renderer must pin webGl:renderer"
    );
}

#[test]
fn header_user_agent_matches_navigator() {
    let cfg = cfg_for(StealthProfile::FirefoxLinux);
    assert_eq!(cfg["headers.User-Agent"], cfg["navigator.userAgent"]);
}

#[test]
fn accept_language_q_values_descend() {
    let al = accept_language(&["en-US".into(), "en".into(), "fr".into()]);
    assert_eq!(al, "en-US,en;q=0.9,fr;q=0.8");
}

#[test]
fn env_is_single_var_for_small_config() {
    let env = reynard_config_env(&profile_to_overrides(&StealthProfile::FirefoxLinux));
    assert_eq!(env.len(), 1);
    assert_eq!(env[0].0, REYNARD_CONFIG_ENV);
    // round-trips as valid JSON
    let parsed: Value = serde_json::from_str(&env[0].1).expect("config is valid JSON");
    assert!(parsed.is_object());
}

#[test]
fn languages_drive_navigator_language() {
    let ov = profile_to_overrides(&StealthProfile::FirefoxLinux);
    let cfg = reynard_config(&ov);
    if let Some(first) = ov.languages.first() {
        assert_eq!(cfg["navigator.language"], json!(first));
    }
}

#[test]
fn full_language_list_populates_locale_all() {
    // Regression for the differential-oracle tell: navigator.languages collapsed
    // to length 1 because the engine derives the array from `intl.accept_languages`
    // (set from `locale:all`), not from the `navigator.languages` config array.
    // FirefoxLinux ships ["en-US","en"] → locale:all must be "en-US, en" so the
    // derived navigator.languages has length 2 and matches a real FF-Linux build.
    let ov = profile_to_overrides(&StealthProfile::FirefoxLinux);
    assert!(
        ov.languages.len() >= 2,
        "FirefoxLinux persona must carry a multi-entry language list"
    );
    let cfg = reynard_config(&ov);
    assert_eq!(
        cfg["locale:all"],
        json!(ov.languages.join(", ")),
        "locale:all must be the full comma-space language list the engine reads first"
    );
    // The single-language fallback alone would have produced length 1; assert the
    // full form carries every entry the persona declares.
    let all = cfg["locale:all"].as_str().unwrap();
    assert_eq!(all.split(", ").count(), ov.languages.len());
}

#[test]
fn wrapper_script_loads_config_and_execs_binary() {
    let s = reynard_wrapper_script("/tmp/cfg.json", "/opt/reynard/firefox");
    assert!(s.starts_with("#!/bin/sh"));
    assert!(
        s.contains(&format!("{REYNARD_CONFIG_ENV}=\"$(cat '/tmp/cfg.json')\"")),
        "wrapper must load config from the file under the reynard env name: {s}"
    );
    assert!(s.contains(&format!("export {REYNARD_CONFIG_ENV}")));
    assert!(
        s.contains("exec '/opt/reynard/firefox' \"$@\""),
        "wrapper must exec the binary forwarding BiDi flags: {s}"
    );
}

#[test]
fn align_ua_to_engine_rewrites_firefox_major() {
    let persona = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0";
    let aligned = align_ua_to_engine(persona, 150);
    assert_eq!(
        aligned,
        "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
    );
    // Gecko build token is NOT a version and must survive untouched.
    assert!(aligned.contains("Gecko/20100101"));
}

#[test]
fn align_ua_to_engine_is_noop_when_matching_or_absent() {
    let persona = "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0";
    assert_eq!(align_ua_to_engine(persona, 150), persona);
    // No Firefox token → unchanged (e.g. a non-Firefox persona).
    let other = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Safari/537.36";
    assert_eq!(align_ua_to_engine(other, 150), other);
}

#[test]
fn identity_seed_is_stable_and_distinct() {
    // Same account key → same seed: a device is stable across that account's
    // own sessions.
    assert_eq!(
        identity_seed("/profiles/acct-a"),
        identity_seed("/profiles/acct-a")
    );
    // Different account keys → different seed: accounts render as different
    // devices (the multi-account un-correlation contract).
    assert_ne!(
        identity_seed("/profiles/acct-a"),
        identity_seed("/profiles/acct-b")
    );
    // A one-char difference still diverges (FNV-1a avalanche).
    assert_ne!(identity_seed("acct-1"), identity_seed("acct-2"));
}

#[test]
fn merge_reynard_prefs_none_is_just_webdriver_pref() {
    assert_eq!(merge_reynard_prefs(None), REYNARD_PROFILE_PREFS);
    assert_eq!(
        merge_reynard_prefs(Some("  ".into())),
        REYNARD_PROFILE_PREFS
    );
}

#[test]
fn merge_reynard_prefs_keeps_caller_prefs() {
    // The bridge may pass proxy/identity prefs; reynard must ADD its pref,
    // never clobber the caller's.
    let merged = merge_reynard_prefs(Some("user_pref(\"network.proxy.type\", 1);".into()));
    assert!(
        merged.contains("network.proxy.type"),
        "caller pref preserved"
    );
    assert!(
        merged.contains("dom.webdriver.enabled"),
        "reynard pref added"
    );
}

#[test]
fn wrapper_forwards_bidi_flags_via_args() {
    // "$@" is load-bearing: rustenium passes --remote-debugging-port etc. and
    // they must reach the real binary, or BiDi never connects.
    assert!(reynard_wrapper_script("/c", "/b").contains("\"$@\""));
}

#[test]
fn resolve_reynard_bin_precedence_and_fallback() {
    // REYNARD_BIN wins over GUISE_REYNARD_BIN and the conventional paths.
    let r = resolve_reynard_bin_from(
        |k| match k {
            "REYNARD_BIN" => Some("/x/reynard".into()),
            "GUISE_REYNARD_BIN" => Some("/y/guise".into()),
            "HOME" => Some("/home/u".into()),
            _ => None,
        },
        |_| true,
    );
    assert_eq!(r.as_deref(), Some("/x/reynard"));

    // A blank REYNARD_BIN is ignored (trimmed-empty), falling through to
    // GUISE_REYNARD_BIN (the bridge's name still resolves).
    let r = resolve_reynard_bin_from(
        |k| match k {
            "REYNARD_BIN" => Some("   ".into()),
            "GUISE_REYNARD_BIN" => Some("/y/guise".into()),
            _ => None,
        },
        |_| true,
    );
    assert_eq!(r.as_deref(), Some("/y/guise"));

    // No env override → first EXISTING conventional path (here only the ~/.cache one).
    let r = resolve_reynard_bin_from(
        |k| (k == "HOME").then(|| "/home/u".into()),
        |p| p == "/home/u/.cache/reynard/reynard",
    );
    assert_eq!(r.as_deref(), Some("/home/u/.cache/reynard/reynard"));

    // Nothing set, nothing installed → None: the caller MUST fall back loudly to
    // plain Firefox (Law 10), never silently treat this as "stealth engine present".
    assert_eq!(resolve_reynard_bin_from(|_| None, |_| false), None);
}
