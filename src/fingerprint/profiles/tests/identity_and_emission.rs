use super::*;

#[test]
fn ua_matches_platform() {
    // Windows UA must pair with Win32 platform; Mac with MacIntel; etc.
    // Mismatches are *more* suspicious than vanilla headless.
    let cases = [
        (StealthProfile::ChromeWindowsStable, "Windows", "Win32"),
        (StealthProfile::ChromeWindowsLegacy96, "Windows", "Win32"),
        (StealthProfile::ChromeMacStable, "Mac OS X", "MacIntel"),
        (StealthProfile::EdgeWindowsStable, "Windows", "Win32"),
        (StealthProfile::Ie11Windows, "Trident/7.0", "Win32"),
        (StealthProfile::FirefoxLinux, "Linux", "Linux x86_64"),
        (StealthProfile::FirefoxWindows, "Windows", "Win32"),
        (StealthProfile::ChromeAndroid, "Android", "Linux armv8l"),
        (StealthProfile::ChromeLinux, "Linux", "Linux x86_64"),
        (StealthProfile::SafariIphone, "iPhone", "iPhone"),
        (StealthProfile::SafariIpad, "iPad", "iPad"),
        (StealthProfile::SafariMacStable, "Mac OS X", "MacIntel"),
        (StealthProfile::BraveWindows, "Windows", "Win32"),
        (StealthProfile::OperaWindows, "Windows", "Win32"),
        (
            StealthProfile::SamsungInternetAndroid,
            "Android",
            "Linux armv8l",
        ),
    ];
    for (p, ua_substr, platform) in cases {
        let ov = profile_to_overrides(&p);
        assert!(
            ov.user_agent.contains(ua_substr),
            "{p:?} UA missing {ua_substr}"
        );
        assert_eq!(ov.platform, platform, "{p:?} platform mismatch");
    }
}

#[test]
fn chrome_windows_user_agent_const_matches_profile() {
    let ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    assert_eq!(ov.user_agent, CHROME_WINDOWS_STABLE_USER_AGENT);
}

#[test]
fn profile_user_agent_matches_materialized_overrides() {
    for profile in ALL_TEST_PROFILES {
        assert_eq!(
            profile_to_overrides(profile).user_agent,
            profile_user_agent(*profile),
            "{profile:?} duplicated UA drifted from profile_user_agent"
        );
    }
}

#[test]
fn materialized_overrides_share_base_identity_facts() {
    for profile in ALL_TEST_PROFILES {
        let facts = profile_facts(*profile);
        let overrides = profile_to_overrides(profile);
        assert_eq!(overrides.user_agent, facts.user_agent);
        assert_eq!(overrides.platform, facts.platform);
        assert_eq!(overrides.mobile, facts.mobile);
        assert_eq!(overrides.screen_width, facts.screen_width);
        assert_eq!(overrides.screen_height, facts.screen_height);
        assert_eq!(
            overrides.languages,
            facts
                .languages
                .iter()
                .map(|language| (*language).to_string())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn navigation_headers_share_base_identity_facts() {
    let facts = profile_facts(StealthProfile::FirefoxLinux);
    assert_eq!(
        profile_navigation_headers(StealthProfile::FirefoxLinux),
        [
            NavigationHeader {
                name: USER_AGENT_HEADER,
                value: facts.user_agent,
            },
            NavigationHeader {
                name: ACCEPT_HEADER,
                value: facts.accept,
            },
            NavigationHeader {
                name: ACCEPT_LANGUAGE_HEADER,
                value: facts.accept_language,
            },
        ]
    );
}

#[test]
fn browser_headers_share_base_identity_facts_with_compression() {
    let facts = profile_facts(StealthProfile::FirefoxLinux);
    assert_eq!(
        profile_browser_headers(StealthProfile::FirefoxLinux),
        [
            NavigationHeader {
                name: USER_AGENT_HEADER,
                value: facts.user_agent,
            },
            NavigationHeader {
                name: ACCEPT_HEADER,
                value: facts.accept,
            },
            NavigationHeader {
                name: ACCEPT_LANGUAGE_HEADER,
                value: facts.accept_language,
            },
            NavigationHeader {
                name: ACCEPT_ENCODING_HEADER,
                value: facts.accept_encoding,
            },
        ]
    );
}

#[test]
fn profile_js_emits_uadata_only_when_brands_present() {
    let chrome = profile_js(&profile_to_overrides(&StealthProfile::ChromeWindowsStable));
    assert!(chrome.contains("userAgentData"));
    // Firefox profile still emits the conditional but the runtime
    // brands.length check skips assignment. Source-level check:
    // the JS must always contain the guard.
    assert!(chrome.contains("brands.length > 0"));
}

#[test]
fn profile_js_high_entropy_client_hints_derive_from_profile() {
    let chrome = profile_js(&profile_to_overrides(&StealthProfile::ChromeWindowsStable));
    assert!(chrome.contains("fullVersionList"));
    assert!(chrome.contains(r#""version":"131.0.0.0""#));
    assert!(chrome.contains("uaFullVersion: \"131.0.0.0\""));
    assert!(!chrome.contains("uaFullVersion: '130.0.0.0'"));

    let linux = profile_js(&profile_to_overrides(&StealthProfile::ChromeLinux));
    assert!(linux.contains("platformVersion: \"\""));
    assert!(linux.contains("platform: \"Linux\""));
}

#[test]
fn profile_js_overrides_webgl_unmasked_params() {
    // A NON-Gecko persona (Chrome/Safari) is injected onto a non-Gecko engine that
    // has no Firefox `webgl.override-unmasked-*` prefs, so profile_js MUST carry the
    // JS getParameter override. Masked GL_VENDOR (0x1F00) is intentionally NOT
    // referenced, it is left native ("Mozilla" on every engine), so assert the
    // FUNCTIONAL constants the override actually uses, plus the pinned renderer.
    let js = profile_js(&profile_to_overrides(&StealthProfile::ChromeMacStable));
    assert!(
        js.contains("0x1F01"),
        "masked GL_RENDERER constant must be referenced"
    );
    assert!(
        js.contains("0x9245"),
        "WebGL UNMASKED_VENDOR constant must be referenced"
    );
    assert!(
        js.contains("0x9246"),
        "WebGL UNMASKED_RENDERER constant must be referenced"
    );
    assert!(
        js.contains("getParameter"),
        "non-Gecko persona must wrap getParameter"
    );
    assert!(
        js.contains("Apple M1 Pro"),
        "Mac profile must pin an Apple GPU renderer"
    );
}

#[test]
fn profile_js_firefox_persona_omits_webgl_getparameter_override() {
    // A FIREFOX persona's WebGL UNMASKED_RENDERER/VENDOR are spoofed at the ENGINE
    // level (webgl.override-unmasked-* prefs in build_user_js), which reach EVERY
    // realm, including a Web Worker's OffscreenCanvas WebGL that a window-realm JS
    // getParameter override cannot touch (that worker leaked the host GPU). So the JS
    // override MUST be absent for Firefox personas; its presence would re-introduce
    // the window/worker form mismatch and the raw (un-sanitized) renderer string.
    for p in [
        StealthProfile::FirefoxWindows,
        StealthProfile::FirefoxMacStable,
        StealthProfile::FirefoxLinux,
    ] {
        let js = profile_js(&profile_to_overrides(&p));
        assert!(
            !js.contains("UNMASKED_RENDERER = 0x9246"),
            "{p:?}: profile_js must NOT carry the WebGL getParameter override (engine pref handles it)"
        );
    }
}

#[test]
fn profile_js_does_not_pin_window_dimensions_but_pins_touch_capability() {
    // Window dimensions (inner/outer Width/Height, screenX/screenY) must NOT be
    // overridden: a JS getter cannot move the real layout viewport
    // (documentElement.clientWidth), matchMedia('(width)'), or screen.*, so a
    // pinned persona size that the real window does not match is a triple
    // contradiction (verified live, dump_geometry_truth). maxTouchPoints IS a real
    // capability signal not contradicted by any layout surface, so it stays pinned.
    let desktop = profile_js(&profile_to_overrides(&StealthProfile::ChromeWindowsStable));
    assert!(
        !desktop.contains("Object.defineProperty(window, 'outerWidth'"),
        "must not pin window.outerWidth (contradicts real screen/layout)"
    );
    assert!(
        !desktop.contains("Object.defineProperty(window, 'innerWidth'"),
        "must not pin window.innerWidth (contradicts clientWidth/matchMedia)"
    );
    assert!(
        !desktop.contains("Object.defineProperty(window, 'innerHeight'"),
        "must not pin window.innerHeight"
    );
    assert!(
        !desktop.contains("Object.defineProperty(window, 'screenY'"),
        "must not pin window.screenY"
    );
    assert!(
        desktop.contains("Object.defineProperty(Navigator.prototype, 'maxTouchPoints'"),
        "maxTouchPoints (a real capability signal) must still be pinned"
    );
    assert!(desktop.contains("get: __seal(() => 0, 'get maxTouchPoints')"));

    let mobile = profile_js(&profile_to_overrides(&StealthProfile::ChromeAndroid));
    assert!(mobile.contains("Object.defineProperty(Navigator.prototype, 'maxTouchPoints'"));
    assert!(mobile.contains("get: __seal(() => 5, 'get maxTouchPoints')"));
}

#[test]
fn profile_js_emits_frozen_firefox_appversion_not_full_ua() {
    // Firefox freezes navigator.appVersion to the OS-family form, NOT
    // userAgent-minus-"Mozilla/". The old override emitted the full UA string, a
    // value no real Firefox reports (verified live, dump_worker_navigator_sweep).
    let cases = [
        (StealthProfile::FirefoxLinux, "5.0 (X11)"),
        (StealthProfile::FirefoxWindows, "5.0 (Windows)"),
        (StealthProfile::FirefoxMacStable, "5.0 (Macintosh)"),
    ];
    for (profile, expected) in cases {
        let js = profile_js(&profile_to_overrides(&profile));
        assert!(
            js.contains(&format!(
                "get: __seal(() => \"{expected}\", 'get appVersion')"
            )),
            "{profile:?} must emit frozen appVersion {expected:?}, got JS:\n{js}"
        );
        assert!(
            !js.contains(".replace('Mozilla/', '')"),
            "{profile:?} must NOT derive appVersion from the full UA (real FF freezes it)"
        );
    }
}

#[test]
fn profile_js_emits_oscpu_coherent_with_persona_os() {
    // navigator.oscpu must be pinned to the persona UA's OS token; a cross-OS
    // Firefox persona otherwise leaks the host OS (a Windows UA reporting
    // oscpu="Linux x86_64" (confirmed live, dump_cross_os_persona_truth)).
    let cases = [
        (StealthProfile::FirefoxLinux, "Linux x86_64"),
        (
            StealthProfile::FirefoxWindows,
            "Windows NT 10.0; Win64; x64",
        ),
        (StealthProfile::FirefoxMacStable, "Intel Mac OS X 10.15"),
    ];
    for (profile, expected) in cases {
        let js = profile_js(&profile_to_overrides(&profile));
        assert!(
            js.contains(&format!("get: __seal(() => \"{expected}\", 'get oscpu')")),
            "{profile:?} must pin oscpu to {expected:?}, got JS:\n{js}"
        );
    }
    // The cross-OS personas must never pin oscpu to the Linux host token.
    for profile in [
        StealthProfile::FirefoxWindows,
        StealthProfile::FirefoxMacStable,
    ] {
        let js = profile_js(&profile_to_overrides(&profile));
        assert!(
            !js.contains("get: __seal(() => \"Linux x86_64\", 'get oscpu')"),
            "{profile:?} must not pin oscpu to the Linux host"
        );
    }
}

#[test]
fn profile_js_suppresses_host_speech_voices_for_cross_os_persona() {
    // A cross-OS persona (non-empty persona renderer) must suppress the host TTS
    // voice list, the host espeak/SAPI set is a cross-OS tell (confirmed live,
    // dump_speech_and_datezone_truth: a Windows persona leaked 13k Linux espeak
    // voices). getVoices() is overridden to return [].
    let win = profile_js(&profile_to_overrides(&StealthProfile::FirefoxWindows));
    assert!(
        win.contains("'getVoices'") && win.contains("return []"),
        "FirefoxWindows must suppress speechSynthesis.getVoices, got JS:\n{win}"
    );
    // A matched persona keeps the native (coherent) voice list (no override).
    let lin = profile_js(&profile_to_overrides(&StealthProfile::FirefoxLinux));
    assert!(
        !lin.contains("'getVoices'"),
        "FirefoxLinux (matched) must NOT override getVoices, got JS:\n{lin}"
    );
}

#[test]
fn profile_js_deletes_oscpu_for_chromium_persona() {
    // A real Chrome has no navigator.oscpu; the Firefox engine exposes it natively,
    // so a Chromium persona must DELETE it (else `'oscpu' in navigator` is a
    // cross-engine tell).
    let js = profile_js(&profile_to_overrides(&StealthProfile::ChromeWindowsStable));
    assert!(
        js.contains("delete Navigator.prototype.oscpu"),
        "Chromium persona must delete navigator.oscpu, got JS:\n{js}"
    );
    assert!(
        !js.contains("'get oscpu')"),
        "Chromium persona must NOT define an oscpu getter (Chrome has none)"
    );
}

#[test]
fn profile_js_pins_navigator_language_singular_and_timezone() {
    let ov = profile_to_overrides(&StealthProfile::ChromeWindowsStable);
    let js = profile_js(&ov);
    // navigator.language (singular) must be pinned to languages[0], pinning only
    // the plural is a known FingerprintJS/CreepJS consistency tell.
    assert!(
        js.contains("Object.defineProperty(Navigator.prototype, 'language'"),
        "navigator.language (singular) must be overridden"
    );
    let primary = ov.languages.first().unwrap();
    assert!(
        js.contains(&format!("get: __seal(() => \"{primary}\", 'get language')")),
        "navigator.language must equal languages[0] ({primary})"
    );
    // And the R056 timezone spoof must be embedded, carrying the persona zone.
    assert!(
        js.contains(&format!(r#""{}""#, ov.timezone)),
        "timezone not embedded"
    );
    assert!(
        js.contains("Date.prototype.getTimezoneOffset ="),
        "timezone spoof must override getTimezoneOffset"
    );
}

#[test]
fn android_profile_is_mobile_with_narrow_screen() {
    let ov = profile_to_overrides(&StealthProfile::ChromeAndroid);
    assert!(ov.mobile);
    assert!(
        ov.screen_width < 500,
        "mobile profile should have a phone-sized screen"
    );
}

#[test]
fn languages_default_to_english() {
    // All shipped profiles start with en-US. Localised profiles are
    // a future addition; for now we ship one consistent set so
    // accept-language headers don't conflict with navigator.languages.
    for p in ALL_TEST_PROFILES {
        let ov = profile_to_overrides(p);
        assert_eq!(ov.languages.first().map(|s| s.as_str()), Some("en-US"));
    }
}

#[test]
fn safari_profiles_have_apple_webgl_renderer() {
    for p in [
        StealthProfile::SafariIphone,
        StealthProfile::SafariIpad,
        StealthProfile::SafariMacStable,
    ] {
        let ov = profile_to_overrides(&p);
        assert!(
            ov.webgl_vendor.contains("Apple"),
            "{p:?} must claim an Apple GPU vendor"
        );
    }
}

#[test]
fn brave_profile_lists_brave_brand_first() {
    let ov = profile_to_overrides(&StealthProfile::BraveWindows);
    let first = ov.brands.first().map(|(b, _)| b.as_str());
    assert_eq!(first, Some("Brave"));
}

#[test]
fn samsung_internet_profile_is_mobile() {
    let ov = profile_to_overrides(&StealthProfile::SamsungInternetAndroid);
    assert!(ov.mobile);
    assert!(ov.user_agent.contains("SamsungBrowser"));
}

#[test]
fn opera_profile_lists_opera_brand() {
    let ov = profile_to_overrides(&StealthProfile::OperaWindows);
    let names: Vec<&str> = ov.brands.iter().map(|(b, _)| b.as_str()).collect();
    assert!(names.contains(&"Opera"));
    assert!(ov.user_agent.contains("OPR/"));
}

#[test]
fn safari_profiles_have_no_brave_or_opera_marker() {
    // Safari profiles must not accidentally inherit Brave/Opera UAs.
    for p in [
        StealthProfile::SafariIphone,
        StealthProfile::SafariIpad,
        StealthProfile::SafariMacStable,
    ] {
        let ov = profile_to_overrides(&p);
        assert!(!ov.user_agent.contains("OPR/"));
        assert!(!ov.user_agent.contains("Brave"));
        assert!(ov.user_agent.contains("Safari/"));
    }
}

#[test]
fn edge_profile_lists_microsoft_brand_distinct_from_chrome() {
    let ov = profile_to_overrides(&StealthProfile::EdgeWindowsStable);
    let brand_names: Vec<&str> = ov.brands.iter().map(|(b, _)| b.as_str()).collect();
    assert!(brand_names.contains(&"Microsoft Edge"));
    assert!(
        !brand_names.contains(&"Google Chrome"),
        "Edge profile must not list Google Chrome - that mismatch is itself a tell"
    );
}
