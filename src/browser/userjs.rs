//! Firefox `user.js` pref-layer builder.
//!
//! Where [`super::inject`] hides tells at the JS runtime layer, this module
//! emits the launch-time Firefox preferences (UA/platform overrides, the
//! marionette/remote disables, hardware concurrency, notification API) that a
//! profile needs set before the first page loads. [`super::launch_profiled_firefox`]
//! merges the output into the launched profile's `user.js`.

/// The automation-hiding / coherence pref lines, with **no identity override**.
///
/// This is the launch-time pref half of stealth, with the genuine identity left
/// intact:
///
/// - `dom.webdriver.enabled=false`. NOTE: on a **plain BiDi-driven Firefox** an
///   active remote agent (which the CLI `--remote-debugging-port` activates, and
///   which BiDi control requires) overrides this pref, so the **native**
///   `navigator.webdriver` stays `true` regardless, verified empirically in
///   `captchaforge/tests/webdriver_native_pref.rs`. The main-world value is
///   instead masked by the JS getter override in [`super::apply_stealth`]; full
///   native coverage (Workers / fresh iframes / pre-preload re-reads, the
///   `webDriverAdvanced` signal) requires the **reynard engine build**, which
///   patches out the automation→`webdriver` coupling so this pref is honoured.
///   The pref is kept here because it IS load-bearing on that engine path.
/// - The Marionette/remote *default* prefs are disabled (the CLI flag still
///   activates the BiDi remote agent, so the automation connection is
///   unaffected, this is the same set [`build_user_js`] /
///   [`super::launch_profiled_firefox`] already ship).
/// - `privacy.resistFingerprinting=false`: RFP's letterboxing + timer
///   quantisation is itself a measurable tell, and it fights the coherent
///   fingerprint the JS layer presents.
/// - The Notification API is kept present (removing it is a measured tell).
///
/// It deliberately sets **no** `general.useragent.override` / `platform` /
/// `accept_languages` / `dom.maxHardwareConcurrency`, so the browser's genuine
/// identity stays self-consistent across JS/HTTP/TLS. Use this for the
/// real-identity default; use [`build_user_js`] for an explicit persona.
pub fn automation_prefs() -> String {
    [
        r#"user_pref("dom.webdriver.enabled", false);"#,
        r#"user_pref("marionette.defaultPrefs.enabled", false);"#,
        r#"user_pref("remote.enabled", false);"#,
        r#"user_pref("remote.frames.enabled", false);"#,
        r#"user_pref("privacy.resistFingerprinting", false);"#,
        r#"user_pref("dom.webnotifications.enabled", true);"#,
        // Profile PERSISTENCE (works WITH foxdriver's clean `browser.close` in
        // Page::close, see that method). The clean close tears down each tab, which
        // force-flushes that origin's LSNG Datastore and dispatches the SQLite write;
        // these two prefs make that flush land reliably:
        //   * `fastShutdownStage=0` runs the FULL shutdown so the QuotaManager phase
        //     WAITS for the dispatched flush op to complete instead of fast-exiting
        //     past it (a fast shutdown could abandon the in-flight write).
        //   * the small snapshot-idle timeout finalizes the content→parent LocalStorage
        //     snapshot promptly, so the parent Datastore already holds the data when
        //     the tab closes.
        // Confirmed live: with a SIGKILL/fast-exit, localStorage read back `null`
        // after a restart reusing the same profile_dir (cookies, flushed eagerly,
        // survived); with the clean close + these prefs, localStorage/IndexedDB
        // persist. Internal prefs, not web-visible (no fingerprint surface).
        r#"user_pref("toolkit.shutdown.fastShutdownStage", 0);"#,
        r#"user_pref("dom.storage.snapshot_idle_timeout_ms", 500);"#,
    ]
    .join("\n")
}

/// Escape a string for use as a double-quoted Firefox `prefs.js` value.
///
/// Firefox's pref parser reads string values as C-style double-quoted literals,
/// so the value must escape `\`, `"`, and, critically, newlines. Escaping only
/// `"` (the old behaviour) left a newline in a caller-supplied override (UA /
/// platform / languages, all reachable via the public [`crate::ProfileOverrides`])
/// to split the `user_pref(...)` call across physical lines: Firefox then fails
/// to parse that pref and the persona override is SILENTLY dropped, so the
/// browser serves its REAL UA while the JS layer claims the persona's, the exact
/// JS-vs-HTTP mismatch this module exists to prevent. Backslash is escaped first
/// so the other escapes are not doubled.
fn escape_pref_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            c => out.push(c),
        }
    }
    out
}

/// Build a `user.js` string from [`crate::ProfileOverrides`].
///
/// Identity overrides (UA / platform / languages / hardwareConcurrency) plus the
/// shared [`automation_prefs`] block. This is the explicit-persona path; for the
/// real-identity default, write only [`automation_prefs`] (no identity override).
pub fn build_user_js(overrides: &crate::ProfileOverrides) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        r#"user_pref("general.useragent.override", "{}");"#,
        escape_pref_value(&overrides.user_agent)
    ));
    lines.push(format!(
        r#"user_pref("general.platform.override", "{}");"#,
        escape_pref_value(&overrides.platform)
    ));
    // `general.appversion.override`: ENGINE-level so it reaches EVERY realm, unlike
    // the window-only JS getter that `profile_js` installs. A Web Worker snapshots
    // `WorkerNavigator.appVersion` from the engine value at creation, so without this
    // pref a cross-OS persona's worker leaked the host OS (`"5.0 (X11)"` under a
    // Windows UA) AND disagreed with the window's getter value, a cross-realm tell
    // (confirmed live, tests/worker_cross_os_live.rs). Driven by the SAME
    // `firefox_app_version` the getter uses, so window and worker are byte-identical.
    lines.push(format!(
        r#"user_pref("general.appversion.override", "{}");"#,
        escape_pref_value(crate::fingerprint::firefox_app_version(&overrides.platform))
    ));
    // WebGL UNMASKED_RENDERER / UNMASKED_VENDOR. ENGINE-level override so EVERY
    // realm (incl. a Web Worker's `OffscreenCanvas` WebGL) reports the persona GPU.
    // The window-only JS `getParameter` override in `profile_js` does NOT reach a
    // worker, so a cross-OS persona's worker leaked the real host GPU (`NVIDIA …`
    // under a Windows UA, both unmasked AND masked, confirmed live,
    // tests/worker_webgl_cross_os_live.rs). Set ONLY for a cross-OS persona (non-empty
    // renderer); a matched-host persona leaves Gecko's own sanitized adapter (most
    // coherent, its pixels match). Masked GL_VENDOR stays "Mozilla" natively (the
    // engine forces it); masked GL_RENDERER becomes `SanitizeRenderer(override)`, the
    // exact form a real Firefox reports.
    if !overrides.webgl_renderer.is_empty() {
        lines.push(format!(
            r#"user_pref("webgl.override-unmasked-renderer", "{}");"#,
            escape_pref_value(&overrides.webgl_renderer)
        ));
    }
    if !overrides.webgl_vendor.is_empty() {
        lines.push(format!(
            r#"user_pref("webgl.override-unmasked-vendor", "{}");"#,
            escape_pref_value(&overrides.webgl_vendor)
        ));
    }
    lines.push(format!(
        r#"user_pref("intl.accept_languages", "{}");"#,
        escape_pref_value(&overrides.languages.join(","))
    ));
    // Shared automation-hiding / coherence prefs (incl. the Notification API
    // rationale documented on `automation_prefs`).
    lines.push(automation_prefs());
    lines.push(format!(
        r#"user_pref("dom.maxHardwareConcurrency", {});"#,
        overrides.hardware_concurrency
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automation_prefs_sets_webdriver_disable_pref() {
        // Pin the pref STRING is emitted. (Runtime effect on plain BiDi is nil
        // the remote agent overrides it; it is honoured only on the reynard
        // engine build. See webdriver_native_pref.rs for the live proof.)
        let p = automation_prefs();
        assert!(p.contains(r#"user_pref("dom.webdriver.enabled", false);"#));
    }

    #[test]
    fn automation_prefs_has_no_identity_overrides() {
        // The max-coherence contract: this block must NOT pin UA / platform /
        // languages / hardwareConcurrency, those would desync the genuine
        // identity from HTTP/TLS.
        let p = automation_prefs();
        assert!(!p.contains("general.useragent.override"), "must not pin UA");
        assert!(
            !p.contains("general.platform.override"),
            "must not pin platform"
        );
        assert!(
            !p.contains("intl.accept_languages"),
            "must not pin languages"
        );
        assert!(
            !p.contains("dom.maxHardwareConcurrency"),
            "must not pin hardwareConcurrency"
        );
    }

    #[test]
    fn automation_prefs_disables_marionette_and_remote_defaults() {
        let p = automation_prefs();
        assert!(p.contains("marionette.defaultPrefs.enabled"));
        assert!(p.contains("remote.enabled"));
        assert!(p.contains("privacy.resistFingerprinting"));
        assert!(p.contains("dom.webnotifications.enabled"));
    }

    #[test]
    fn automation_prefs_lines_are_valid_pref_format() {
        for line in automation_prefs().lines() {
            assert!(
                line.starts_with("user_pref(") && line.ends_with(");"),
                "invalid pref line: {line}"
            );
        }
    }

    #[test]
    fn build_user_js_includes_automation_prefs_block() {
        // build_user_js must keep shipping the shared automation block (it is the
        // launch-time half of stealth; a regression here re-exposes webdriver).
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        let js = build_user_js(&overrides);
        for line in automation_prefs().lines() {
            assert!(
                js.contains(line),
                "build_user_js missing automation pref: {line}"
            );
        }
    }

    #[test]
    fn build_user_js_contains_useragent_override() {
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        let js = build_user_js(&overrides);
        assert!(js.contains("general.useragent.override"));
    }

    #[test]
    fn build_user_js_contains_platform_override() {
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        let js = build_user_js(&overrides);
        assert!(js.contains("general.platform.override"));
    }

    #[test]
    fn build_user_js_appversion_override_is_persona_os_coherent() {
        // The engine `general.appversion.override` pref (the half that reaches a Web
        // Worker's WorkerNavigator, unlike the window-only getter) must carry the
        // persona OS's reduced appVersion, byte-identical to the window getter's
        // value, so window and worker realms agree. Asserts the VALUE, not just
        // presence (a Windows persona emitting "5.0 (X11)" was the worker leak).
        let win = build_user_js(&crate::profile_to_overrides(
            &crate::StealthProfile::FirefoxWindows,
        ));
        assert!(
            win.contains(r#"user_pref("general.appversion.override", "5.0 (Windows)");"#),
            "Windows persona appversion.override not coherent: {win}"
        );
        let lin = build_user_js(&crate::profile_to_overrides(
            &crate::StealthProfile::FirefoxLinux,
        ));
        assert!(
            lin.contains(r#"user_pref("general.appversion.override", "5.0 (X11)");"#),
            "Linux persona appversion.override not coherent: {lin}"
        );
        let mac = build_user_js(&crate::profile_to_overrides(
            &crate::StealthProfile::FirefoxMacStable,
        ));
        assert!(
            mac.contains(r#"user_pref("general.appversion.override", "5.0 (Macintosh)");"#),
            "Mac persona appversion.override not coherent: {mac}"
        );
    }

    #[test]
    fn build_user_js_contains_languages() {
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        let js = build_user_js(&overrides);
        assert!(js.contains("intl.accept_languages"));
    }

    #[test]
    fn build_user_js_disables_webdriver() {
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        let js = build_user_js(&overrides);
        assert!(js.contains("dom.webdriver.enabled"));
        assert!(js.contains("false"));
    }

    #[test]
    fn build_user_js_disables_marionette() {
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        let js = build_user_js(&overrides);
        assert!(js.contains("marionette.defaultPrefs.enabled"));
    }

    #[test]
    fn build_user_js_disables_resist_fingerprinting() {
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        let js = build_user_js(&overrides);
        assert!(js.contains("privacy.resistFingerprinting"));
    }

    #[test]
    fn build_user_js_contains_webnotifications_pref() {
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        let js = build_user_js(&overrides);
        assert!(js.contains("dom.webnotifications.enabled"));
    }

    #[test]
    fn build_user_js_contains_hardware_concurrency() {
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        let js = build_user_js(&overrides);
        assert!(js.contains("dom.maxHardwareConcurrency"));
    }

    #[test]
    fn build_user_js_lines_are_valid_pref_format() {
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        let js = build_user_js(&overrides);
        for line in js.lines() {
            if line.trim().is_empty() {
                continue;
            }
            assert!(
                line.starts_with("user_pref(") && line.ends_with(");"),
                "invalid pref line: {}",
                line
            );
        }
    }

    #[test]
    fn build_user_js_escapes_quotes() {
        let mut overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        overrides.user_agent = r#"Mozilla/5.0 "test" browser"#.into();
        let js = build_user_js(&overrides);
        assert!(js.contains(r#"\"test\""#));
    }

    #[test]
    fn build_user_js_empty_languages_does_not_panic() {
        let mut overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        overrides.languages.clear();
        let _ = build_user_js(&overrides);
    }

    #[test]
    fn build_user_js_firefox_windows_profile() {
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxWindows);
        let js = build_user_js(&overrides);
        assert!(js.contains("Windows") || js.contains("Win32"));
        assert!(js.contains("general.useragent.override"));
    }

    #[test]
    fn build_user_js_chrome_profile_contains_chrome_ua() {
        let overrides = crate::profile_to_overrides(&crate::StealthProfile::ChromeWindowsStable);
        let js = build_user_js(&overrides);
        assert!(js.contains("Chrome/") || js.contains("Chromium"));
    }

    #[test]
    fn build_user_js_empty_user_agent() {
        let mut overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        overrides.user_agent.clear();
        let js = build_user_js(&overrides);
        assert!(js.contains(r#"user_pref("general.useragent.override", "");"#));
    }

    #[test]
    fn build_user_js_escapes_newline_in_user_agent() {
        // A newline in an override MUST be escaped to the two-char sequence `\n`,
        // never emitted as a literal newline (which would split the pref across
        // physical lines, break Firefox parsing, and silently drop the persona UA
        // → real UA leaks while JS claims the persona's). Every emitted line must
        // still be a single valid `user_pref(...)` statement.
        let mut overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        overrides.user_agent = "line1\nline2".into();
        let js = build_user_js(&overrides);
        // The escaped value is the two characters backslash + n, not a real newline.
        assert!(
            js.contains(r"line1\nline2"),
            "newline must be escaped to the two-char sequence \\n, got: {js}"
        );
        assert!(
            !js.contains("line1\nline2"),
            "a literal newline must not survive inside the pref value"
        );
        // The UA override stays one physical line.
        let ua_line = js
            .lines()
            .find(|l| l.contains("general.useragent.override"))
            .expect("UA override line present");
        assert!(
            ua_line.starts_with("user_pref(") && ua_line.ends_with(");"),
            "UA override must be a single valid pref line: {ua_line}"
        );
    }

    #[test]
    fn build_user_js_escapes_backslash_and_control_chars() {
        let mut overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        overrides.user_agent = "a\\b\tc\rd".into();
        let js = build_user_js(&overrides);
        let ua_line = js
            .lines()
            .find(|l| l.contains("general.useragent.override"))
            .expect("UA override line present");
        // Backslash doubled, tab/CR escaped (and the result is one valid line).
        assert!(
            ua_line.contains(r"a\\b"),
            "backslash must be doubled: {ua_line}"
        );
        assert!(ua_line.contains(r"\t"), "tab must be escaped: {ua_line}");
        assert!(ua_line.contains(r"\r"), "CR must be escaped: {ua_line}");
        assert!(ua_line.starts_with("user_pref(") && ua_line.ends_with(");"));
    }

    #[test]
    fn build_user_js_all_lines_valid_even_with_hostile_override() {
        // The whole-file invariant the format depends on: every non-empty line is
        // a single `user_pref(...)` statement, even when an override carries
        // newlines/quotes (a caller-supplied value via the public ProfileOverrides).
        let mut overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        overrides.user_agent = "evil\");\nuser_pref(\"dom.webdriver.enabled\", true);//".into();
        let js = build_user_js(&overrides);
        for line in js.lines().filter(|l| !l.trim().is_empty()) {
            assert!(
                line.starts_with("user_pref(") && line.ends_with(");"),
                "hostile override broke pref-file line structure: {line}"
            );
        }
        // The injected webdriver-enable pref must NOT appear as its own real line.
        assert!(
            !js.lines()
                .any(|l| l.trim() == r#"user_pref("dom.webdriver.enabled", true);"#),
            "override must not be able to inject a separate pref"
        );
    }

    #[test]
    fn build_user_js_zero_hardware_concurrency() {
        let mut overrides = crate::profile_to_overrides(&crate::StealthProfile::FirefoxLinux);
        overrides.hardware_concurrency = 0;
        let js = build_user_js(&overrides);
        assert!(js.contains("user_pref(\"dom.maxHardwareConcurrency\", 0);"));
    }
}
