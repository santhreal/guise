use super::*;

/// JS-aware bracket-balance check: strips `//` line comments, `/* */` block
/// comments (first `*/` closes, exactly like a real parser), and `'`/`"`/`` ` ``
/// strings (honouring `\` escapes), then verifies every `()[]{}` is matched.
///
/// This is the cheap, browser-free guard for the bug class that silently turned
/// the entire per-profile stealth layer into a no-op: a `*/` sequence *inside* a
/// block comment (`(width/height/avail*/colorDepth)`) closed the comment early,
/// spilling comment prose into code as a `SyntaxError`. A correct comment-strip
/// surfaces the resulting stray bracket as a negative/non-zero depth here.
fn js_brackets_balanced(src: &str) -> Result<(), String> {
    #[derive(PartialEq)]
    enum S {
        Normal,
        Line,
        Block,
        Str(char),
    }
    let b = src.as_bytes();
    let mut st = S::Normal;
    let mut depth: i64 = 0;
    let mut i = 0;
    let mut escape = false;
    while i < b.len() {
        let c = b[i] as char;
        let next = if i + 1 < b.len() {
            b[i + 1] as char
        } else {
            '\0'
        };
        match st {
            S::Normal => match c {
                '/' if next == '/' => {
                    st = S::Line;
                    i += 2;
                    continue;
                }
                '/' if next == '*' => {
                    st = S::Block;
                    i += 2;
                    continue;
                }
                '\'' | '"' | '`' => st = S::Str(c),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth < 0 {
                        return Err(format!("unbalanced '{c}' at byte {i} (depth < 0)"));
                    }
                }
                _ => {}
            },
            S::Line => {
                if c == '\n' {
                    st = S::Normal;
                }
            }
            S::Block => {
                if c == '*' && next == '/' {
                    st = S::Normal;
                    i += 2;
                    continue;
                }
            }
            S::Str(delim) => {
                if escape {
                    escape = false;
                } else if c == '\\' {
                    escape = true;
                } else if c == delim {
                    st = S::Normal;
                }
            }
        }
        i += 1;
    }
    if depth != 0 {
        return Err(format!("unbalanced brackets: final depth {depth}"));
    }
    if st != S::Normal {
        return Err("unterminated string or comment".into());
    }
    Ok(())
}

#[test]
fn profile_js_is_syntactically_balanced_for_all_profiles() {
    for p in ALL_TEST_PROFILES {
        let overrides = profile_to_overrides(p);
        let js = profile_js(&overrides);
        js_brackets_balanced(&js)
            .unwrap_or_else(|e| panic!("profile_js for {p:?} is malformed: {e}"));
    }
}

#[test]
fn js_brackets_balanced_catches_premature_comment_close() {
    // The exact historical bug: a `*/` inside a block comment closes it early,
    // spilling `colorDepth/pixelDepth)` into code with a stray `)`.
    let bad = "(() => { /* screen.* (width/height/avail*/colorDepth/pixelDepth) NOT */ })()";
    assert!(
        js_brackets_balanced(bad).is_err(),
        "must catch premature */"
    );
    let good = "(() => { /* screen.* (width/height/availWidth/colorDepth/pixelDepth) NOT */ })()";
    assert!(
        js_brackets_balanced(good).is_ok(),
        "clean comment must pass"
    );
}

#[test]
fn every_chromium_profile_has_brands() {
    for p in [
        StealthProfile::ChromeWindowsStable,
        StealthProfile::ChromeWindowsLegacy96,
        StealthProfile::ChromeMacStable,
        StealthProfile::EdgeWindowsStable,
        StealthProfile::ChromeAndroid,
        StealthProfile::ChromeLinux,
        StealthProfile::BraveWindows,
        StealthProfile::OperaWindows,
        StealthProfile::SamsungInternetAndroid,
    ] {
        let ov = profile_to_overrides(&p);
        assert!(
            !ov.brands.is_empty(),
            "{p:?} should declare userAgentData brands"
        );
    }
}

#[test]
fn chromium_client_hints_derive_full_versions_from_profile_user_agents() {
    let chrome = profile_client_hints(&StealthProfile::ChromeWindowsStable)
        .expect("Chrome should expose User-Agent Client Hints");
    assert!(chrome
        .full_version_list
        .iter()
        .any(|entry| { entry.brand == "Google Chrome" && entry.version == "131.0.0.0" }));
    assert!(chrome
        .full_version_list
        .iter()
        .any(|entry| entry.brand == "Not?A_Brand" && entry.version == "99.0.0.0"));
    assert_eq!(chrome.ua_full_version, "131.0.0.0");
    assert_eq!(chrome.platform, "Windows");
    assert_eq!(chrome.platform_version, "15.0.0");
    assert_eq!(chrome.architecture, "x86");
    assert_eq!(chrome.bitness, "64");

    let opera = profile_client_hints(&StealthProfile::OperaWindows)
        .expect("Opera should expose Chromium Client Hints");
    assert!(opera
        .full_version_list
        .iter()
        .any(|entry| entry.brand == "Opera" && entry.version == "116.0.0.0"));
    assert!(opera
        .full_version_list
        .iter()
        .any(|entry| entry.brand == "Chromium" && entry.version == "131.0.0.0"));
    assert_eq!(opera.ua_full_version, "116.0.0.0");

    let samsung = profile_client_hints(&StealthProfile::SamsungInternetAndroid)
        .expect("Samsung Internet should expose Chromium Client Hints");
    assert!(samsung
        .full_version_list
        .iter()
        .any(|entry| { entry.brand == "Samsung Internet" && entry.version == "26.0.0.0" }));
    assert!(samsung
        .full_version_list
        .iter()
        .any(|entry| entry.brand == "Chromium" && entry.version == "126.0.0.0"));
    assert_eq!(samsung.platform, "Android");
    assert_eq!(samsung.platform_version, "14.0.0");
    assert_eq!(samsung.architecture, "arm");
    assert_eq!(samsung.bitness, "");
    assert_eq!(samsung.model, "SM-S928B");
}

#[test]
fn non_chromium_profiles_have_no_client_hints() {
    for profile in [
        StealthProfile::FirefoxLinux,
        StealthProfile::FirefoxWindows,
        StealthProfile::SafariIphone,
        StealthProfile::SafariIpad,
        StealthProfile::SafariMacStable,
        StealthProfile::Ie11Windows,
    ] {
        assert!(
            profile_client_hints(&profile).is_none(),
            "{profile:?} must not expose User-Agent Client Hints"
        );
        let overrides = profile_to_overrides(&profile);
        assert_eq!(client_hint_brands_json(&overrides), "[]");
        assert_eq!(client_hint_full_version_list_json(&overrides), "[]");
    }
}

/// A degenerate override whose brand list is entirely GREASE filler (or empty)
/// must never emit an EMPTY `Sec-CH-UA-Full-Version` — no real browser sends
/// one, so `""` is a fingerprint tell. When no non-GREASE brand version exists,
/// the full version is derived from the UA's `Chrome/` token instead.
#[test]
fn all_grease_brands_derive_full_version_from_ua_never_empty() {
    let mut overrides = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    // Every brand is GREASE filler: `full_version_for_brand` maps any brand
    // containing "Brand" (and any "99" major) to "99.0.0.0", so
    // `preferred_ua_full_version` returns `None` and the derivation path runs.
    overrides.brands = vec![
        ("Not?A_Brand".to_string(), "99".to_string()),
        ("Not:A-Brand".to_string(), "8".to_string()),
    ];

    // The canonical Chrome UA carries `Chrome/<full version>`; that token is the
    // coherent source we must fall back to.
    let expected = overrides
        .user_agent
        .split("Chrome/")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("canonical Chrome UA must carry a Chrome/ token")
        .to_string();

    let hints = client_hints_from_overrides(&overrides)
        .expect("an all-GREASE brand list with a Chromium UA must still resolve");
    assert!(
        !hints.ua_full_version.is_empty(),
        "ua_full_version must never be empty for a Chromium UA"
    );
    assert_eq!(
        hints.ua_full_version, expected,
        "ua_full_version must be derived verbatim from the UA's Chrome/ token, not an empty default"
    );
}

/// When the brand list is all-GREASE AND the UA is not Chromium-family (no
/// `Chrome/` token), no coherent full version can be derived, so the persona is
/// rejected (fail closed) rather than shipped with an empty Full-Version header.
#[test]
fn all_grease_brands_with_non_chromium_ua_fails_closed() {
    let mut overrides = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    overrides.brands = vec![("Not?A_Brand".to_string(), "99".to_string())];
    // A Firefox UA has no `Chrome/` token, so the derivation cannot succeed.
    overrides.user_agent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0"
            .to_string();

    assert!(
        client_hints_from_overrides(&overrides).is_none(),
        "an all-GREASE brand list with a non-Chromium UA must fail closed, not emit an empty Full-Version"
    );
}

#[test]
fn hardware_variants_are_profile_coherent() {
    for profile in ALL_TEST_PROFILES {
        let variants = profile_hardware_variants(*profile);
        assert!(!variants.is_empty(), "{profile:?} has no hardware variants");

        for hardware in variants {
            assert!(hardware.screen_width > 0, "{profile:?} width is zero");
            assert!(hardware.screen_height > 0, "{profile:?} height is zero");
            assert!(
                matches!(hardware.color_depth, 24 | 30),
                "{profile:?} has uncommon color depth {}",
                hardware.color_depth
            );
            assert!(
                hardware.hardware_concurrency >= 4,
                "{profile:?} reports too few logical cores"
            );
            assert!(hardware.device_memory >= 4, "{profile:?} memory too low");
            // WebGL vendor/renderer must be COHERENT: either both empty (native
            // passthrough, a matched-host persona exposes the host's real,
            // Gecko-sanitized adapter, whose pixels match) or both pinned (a
            // cross-OS persona supplying a coherent adapter for its claimed OS).
            // A half-state, empty vendor with a non-empty renderer, or vice
            // versa, is the exact incoherence the old generic override shipped
            // ("" vendor + "…GTX 1050 Ti" renderer) and is never valid.
            assert_eq!(
                hardware.webgl_vendor.is_empty(),
                hardware.webgl_renderer.is_empty(),
                "{profile:?} half-spoofed WebGL adapter (vendor/renderer emptiness disagree)"
            );

            let facts = profile_facts(*profile);
            if facts.mobile {
                assert!(
                    hardware.screen_width <= 1024,
                    "{profile:?} mobile profile has desktop width"
                );
            } else {
                assert!(
                    hardware.screen_width >= 1024,
                    "{profile:?} desktop profile has mobile width"
                );
            }
        }
    }
}

#[test]
fn default_hardware_matches_materialized_overrides() {
    for profile in ALL_TEST_PROFILES {
        let hardware = profile_hardware(*profile);
        let overrides = profile_to_overrides(profile);

        assert_eq!(overrides.screen_width, hardware.screen_width);
        assert_eq!(overrides.screen_height, hardware.screen_height);
        assert_eq!(overrides.color_depth, hardware.color_depth);
        assert_eq!(
            overrides.hardware_concurrency,
            u32::from(hardware.hardware_concurrency)
        );
        assert_eq!(overrides.device_memory, u32::from(hardware.device_memory));
        assert_eq!(overrides.webgl_vendor, hardware.webgl_vendor);
        assert_eq!(overrides.webgl_renderer, hardware.webgl_renderer);
    }
}

#[test]
fn indexed_hardware_overrides_apply_selected_variant() {
    let profile = StealthProfile::ChromeWindowsStable;
    let hardware = profile_hardware_at(profile, 2);
    let overrides = profile_to_overrides_at(&profile, 2);

    assert_eq!(overrides.screen_width, hardware.screen_width);
    assert_eq!(overrides.screen_height, hardware.screen_height);
    assert_eq!(overrides.webgl_vendor, "Google Inc. (AMD)");
    assert!(overrides.webgl_renderer.contains("Radeon RX 6700 XT"));
}

#[test]
fn safari_and_firefox_have_no_brands() {
    for p in [
        StealthProfile::FirefoxLinux,
        StealthProfile::FirefoxWindows,
        StealthProfile::SafariIphone,
        StealthProfile::SafariIpad,
        StealthProfile::SafariMacStable,
    ] {
        let ov = profile_to_overrides(&p);
        assert!(
            ov.brands.is_empty(),
            "{p:?} does not expose userAgentData / Client Hints"
        );
    }
}
