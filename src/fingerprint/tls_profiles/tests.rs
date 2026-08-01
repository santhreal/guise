use super::*;
use crate::fingerprint::ja3::{compute_ja3, compute_ja3_hash};

#[test]
fn all_profiles_have_required_fields() {
    for profile in profiles() {
        assert!(!profile.name.is_empty());
        assert!(!profile.cipher_suites.is_empty());
        assert!(!profile.extensions.is_empty());
        assert!(!profile.elliptic_curves.is_empty());
        assert!(!profile.ec_point_formats.is_empty());
        assert!(!profile.alpn_protocols.is_empty());
        assert!(!profile.expected_ja3.is_empty());
        assert!(!profile.signature_algorithms.is_empty());
    }
}

#[test]
fn profiles_count() {
    assert!(profiles().len() >= 6);
}

#[test]
fn profile_for_finds_chrome() {
    assert!(profile_for("chrome").unwrap().name.contains("Chrome"));
}

#[test]
fn profile_for_finds_firefox() {
    assert!(profile_for("firefox").unwrap().name.contains("Firefox"));
}

#[test]
fn profile_for_resolves_shared_stealth_profile_aliases_first() {
    // chrome-mac resolves to the OS-independent measured Chrome 146 (Chrome's
    // BoringSSL ClientHello, like Firefox's NSS, is identical across Win/Linux/Mac
    // for a version, so all modern-stable Chrome personas share one shape rather
    // than the old 3-cipher CHROME_122/CHROME_120 placeholders).
    assert_eq!(profile_for("chrome-mac").unwrap().name, "Chrome 146");
    // FirefoxWindows now resolves to the OS-independent measured FF-150 shape,
    // coherently paired with its Firefox/150 persona UA (it formerly mapped to the
    // EOL FF-115-ESR profile under a stale Firefox/133 UA, both halves of that
    // incoherence are now fixed: UA major == TLS profile major).
    assert_eq!(profile_for("firefox-windows").unwrap().name, "Firefox 150");
    // iPhone persona resolves to the measured iOS Safari-18 coretls shape (its
    // ClientHello is byte-identical to macOS `SAFARI_18`: Apple ships one coretls
    // per Safari major, but the profile is named for iOS so the persona's TLS
    // profile name stays platform-coherent). Replaces the Chrome-borrowed
    // "Safari iOS 17 / iPhone" placeholder.
    assert_eq!(
        profile_for("safari-iphone").unwrap().name,
        "Safari 18 / iOS"
    );
    assert!(profile_for("ie11").is_none());
}

#[test]
fn profile_for_rejects_empty_browser_name() {
    assert!(profile_for("").is_none());
    assert!(profile_for(" \t\n").is_none());
}

#[test]
fn profile_for_returns_none_for_unknown() {
    assert!(profile_for("netscape").is_none());
}

#[test]
fn profile_for_stealth_profile_covers_rotation_profiles() {
    for profile in crate::rotation::profiles() {
        assert!(
            profile_for_stealth_profile(*profile).is_some(),
            "{profile:?} must map to a TLS ClientHello catalogue entry"
        );
    }
}

#[test]
fn legacy_ie_has_no_coherent_tls_catalogue_profile() {
    assert!(profile_for_stealth_profile(StealthProfile::Ie11Windows).is_none());
}

#[cfg(feature = "http")]
#[test]
fn default_impersonate_profile_uses_shared_profile_catalogue() {
    assert_eq!(
        default_impersonate_profile_for_stealth_profile(StealthProfile::ChromeMacStable),
        ImpersonateProfile::Chrome131
    );
    assert_eq!(
        default_impersonate_profile_for_stealth_profile(StealthProfile::FirefoxWindows),
        ImpersonateProfile::Firefox133
    );
    // iPhone/iPad default to the mobile SafariIpad18 wire emulation (measured
    // iOS coretls shape + iOS UA); macOS Safari defaults to desktop Safari18, both
    // bumped from the older 17.5 so the default wire major matches the pure
    // catalogue profile major (18).
    assert_eq!(
        default_impersonate_profile_for_stealth_profile(StealthProfile::SafariIphone),
        ImpersonateProfile::SafariIpad18
    );
    assert_eq!(
        default_impersonate_profile_for_stealth_profile(StealthProfile::SafariIpad),
        ImpersonateProfile::SafariIpad18
    );
    assert_eq!(
        default_impersonate_profile_for_stealth_profile(StealthProfile::SafariMacStable),
        ImpersonateProfile::Safari18
    );
}

#[cfg(feature = "http")]
#[test]
fn impersonate_compatibility_tracks_browser_family() {
    assert!(impersonate_profile_matches_stealth_profile(
        StealthProfile::ChromeWindowsStable,
        ImpersonateProfile::Chrome131
    ));
    assert!(impersonate_profile_matches_stealth_profile(
        StealthProfile::BraveWindows,
        ImpersonateProfile::Edge131
    ));
    assert!(!impersonate_profile_matches_stealth_profile(
        StealthProfile::FirefoxLinux,
        ImpersonateProfile::Chrome131
    ));
    assert!(!impersonate_profile_matches_stealth_profile(
        StealthProfile::Ie11Windows,
        ImpersonateProfile::Chrome120
    ));
}

#[test]
fn random_profile_returns_valid() {
    for _ in 0..50 {
        assert!(!random_profile().unwrap().name.is_empty());
    }
}

#[test]
fn build_cipher_suites_includes_grease_for_chrome() {
    let profile = profile_for("chrome").unwrap();
    assert!(profile.include_grease);
    let suites = build_cipher_suites(profile);
    assert_eq!(suites.len(), profile.cipher_suites.len() + 1);
    assert!(GREASE_VALUES.contains(&suites[0]));
}

#[test]
fn build_cipher_suites_no_grease_for_firefox() {
    let profile = profile_for("firefox").unwrap();
    assert!(!profile.include_grease);
    let suites = build_cipher_suites(profile);
    assert_eq!(suites.len(), profile.cipher_suites.len());
}

#[test]
fn build_extensions_includes_grease_at_both_edges() {
    let profile = profile_for("chrome").unwrap();
    let extensions = build_extensions(profile);
    assert_eq!(extensions.len(), profile.extensions.len() + 2);
    assert!(GREASE_VALUES.contains(extensions.first().unwrap()));
    assert!(GREASE_VALUES.contains(extensions.last().unwrap()));
}

#[test]
fn ja3_string_format_uses_five_dash_joined_sections() {
    let profile = profile_for("chrome").unwrap();
    let ja3 = compute_ja3_string(profile);
    let sections: Vec<&str> = ja3.split(',').collect();
    assert_eq!(sections.len(), 5);
    assert!(sections[0].parse::<u16>().is_ok());
    assert!(sections[1].contains('-'));
    assert!(sections[2].contains('-'));
    assert!(sections[3].contains('-'));
}

#[test]
fn ja3_string_delegates_to_shared_ja3_renderer() {
    let profile = profile_for("chrome").unwrap();
    let fields = client_hello_fields(profile);
    assert_eq!(compute_ja3_string(profile), compute_ja3(&fields));
}

#[test]
fn chrome_and_firefox_have_different_cipher_order() {
    let chrome = profile_for("chrome").unwrap();
    let firefox = profile_for("firefox").unwrap();
    assert_ne!(chrome.cipher_suites[1], firefox.cipher_suites[1]);
}

#[test]
fn chrome_and_firefox_have_different_sig_algs() {
    let chrome = profile_for("chrome").unwrap();
    let firefox = profile_for("firefox").unwrap();
    assert!(firefox.signature_algorithms.contains(&0x0603));
    assert!(!chrome.signature_algorithms.contains(&0x0603));
}

#[test]
fn grease_values_are_valid() {
    for grease in GREASE_VALUES {
        assert_eq!(grease & 0x0f0f, 0x0a0a);
    }
}

#[test]
fn expected_ja3_values_are_md5_hex() {
    for profile in profiles() {
        assert_eq!(profile.expected_ja3.len(), 32, "{}", profile.name);
        assert!(
            profile
                .expected_ja3
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
            "{}",
            profile.name
        );
    }
}

#[test]
fn expected_ja3_equals_md5_of_computed_ja3_string() {
    // `expected_ja3` is a SELF-checksum: md5 of this profile's own computed JA3
    // string, not a fabricated real-browser hash. This locks that contract so a
    // later cipher/extension/curve edit cannot leave a stale value behind, and so
    // nobody can paste a borrowed real-world hash that the field shapes do not
    // actually produce.
    for profile in profiles() {
        let computed = compute_ja3_hash(&client_hello_fields(profile));
        assert_eq!(
            profile.expected_ja3, computed,
            "{}: expected_ja3 is not md5 of its own computed JA3 string",
            profile.name
        );
    }
}

#[test]
fn profile_summary_readable() {
    for profile in profiles() {
        let summary = profile_summary(profile);
        assert!(summary.contains(profile.name));
        assert!(summary.contains("ciphers"));
        assert!(summary.contains("ALPN"));
    }
}

#[test]
fn alpn_offers_match_each_client_family() {
    // Every profile offers http/1.1. The h2 offer is per-client, NOT universal:
    // browsers and curl advertise `h2, http/1.1`, but the measured python-requests/
    // urllib3 reference client is HTTP/1.1-only (live capture: JA4 `…h1`, no h2)
    // claiming h2 there would be an inaccurate ALPN, the exact tell this catalogue
    // exists to avoid. So assert the real contract, not a blanket h2 assumption.
    const HTTP11_ONLY: &[&str] = &["Python requests / urllib3 (OpenSSL 3.0.13)"];
    for profile in profiles() {
        assert!(
            profile.alpn_protocols.contains(&"http/1.1"),
            "{} must offer http/1.1",
            profile.name
        );
        if HTTP11_ONLY.contains(&profile.name) {
            assert!(
                !profile.alpn_protocols.contains(&"h2"),
                "{} is a measured HTTP/1.1-only client and must NOT advertise h2",
                profile.name
            );
        } else {
            assert!(
                profile.alpn_protocols.contains(&"h2"),
                "{} (browser/curl family) must offer h2",
                profile.name
            );
        }
    }
}

#[test]
fn all_profiles_include_sni_extension() {
    for profile in profiles() {
        assert!(
            profile.extensions.contains(&0x0000),
            "{} missing SNI extension",
            profile.name
        );
    }
}

#[test]
fn all_profiles_include_alpn_extension() {
    for profile in profiles() {
        assert!(
            profile.extensions.contains(&0x0010),
            "{} missing ALPN extension",
            profile.name
        );
    }
}

#[test]
fn build_supported_groups_includes_grease_for_chrome() {
    let profile = profile_for("chrome").unwrap();
    assert!(profile.include_grease);
    let groups = build_supported_groups(profile);
    assert_eq!(groups.len(), profile.elliptic_curves.len() + 1);
    assert!(GREASE_VALUES.contains(&groups[0]));
}

#[test]
fn build_supported_groups_no_grease_for_firefox() {
    let profile = profile_for("firefox").unwrap();
    assert!(!profile.include_grease);
    let groups = build_supported_groups(profile);
    assert_eq!(groups.len(), profile.elliptic_curves.len());
    for group in &groups {
        assert!(!GREASE_VALUES.contains(group));
    }
}

#[test]
fn build_supported_groups_preserves_order() {
    let profile = profile_for("chrome").unwrap();
    let groups = build_supported_groups(profile);
    let start = if profile.include_grease { 1 } else { 0 };
    assert_eq!(&groups[start..], profile.elliptic_curves);
}

#[test]
fn every_profile_advertises_tls13_in_supported_versions() {
    // All shipped profiles are TLS 1.3 clients; the legacy field is 0x0303 for
    // middlebox compat but supported_versions must carry 0x0304.
    for profile in profiles() {
        assert_eq!(profile.tls_version, 0x0303, "{}", profile.name);
        assert!(
            profile.supported_versions.contains(&0x0304),
            "{} must offer TLS 1.3 in supported_versions",
            profile.name
        );
    }
}

#[test]
fn every_profile_ja4_reports_tls13_not_the_legacy_field() {
    // The wire-accuracy guard: JA4 must read the negotiated TLS 1.3 from
    // supported_versions (t13), matching what reynard/stock FF emit. NOT the
    // legacy 0x0303 field, which would mislabel every modern client as t12.
    for profile in profiles() {
        let ja4 = compute_ja4_string(profile);
        assert!(
            ja4.starts_with("t13d"),
            "{} JA4 must start with t13d (TLS 1.3), got {ja4}",
            profile.name
        );
    }
}

#[test]
fn computed_profile_ja4_matches_the_published_target_catalogue() {
    // Cross-source coherence (Vectors 7/10), the JA4 twin of the H2 model↔catalogue
    // gate. The `tls_profiles` catalog COMPUTES a JA4 from a real ClientHello;
    // `fingerprint::tls_targets` PUBLISHES a JA4 literal per browser. These are two
    // sources of one fingerprint and were never directly compared, so a profile edit
    // could compute a JA4 that no longer equals the catalogue a persona is
    // classified against. JA4 (not JA3) is the sound axis here: JA4 SORTS extensions,
    // so it is stable even for Chrome's per-connection-randomized TLS extension order
    // (whereas the catalogue's Chrome JA3 string is an order-dependent sample).
    // Chrome/Firefox are wire-measured (2026-06-12), they MUST match. Safari has no
    // Apple-hardware capture on this fleet and is checked separately below.
    use crate::fingerprint::tls_targets::lookup;
    assert_eq!(
        compute_ja4_string(&CHROME_146),
        lookup("chrome-146-linux").unwrap().ja4,
        "CHROME_146 profile JA4 drifted from the published chrome-146 target"
    );
    assert_eq!(
        compute_ja4_string(&FIREFOX_150),
        lookup("firefox-150-linux").unwrap().ja4,
        "FIREFOX_150 profile JA4 drifted from the published firefox-150 target"
    );
}

#[test]
fn every_rotation_persona_ja4_collides_with_a_populated_real_browser_cluster() {
    // Anti-uniqueness guard (G048/G049). A fingerprint that no real browser shares
    // is itself a stable tracking identifier, even if every field is "correct" in
    // isolation. Every persona in the normal rotation must emit a JA4 that collides
    // with a measured, populated real-browser cluster (the built-in target catalogue
    // plus the measured Safari-18 shape). Legacy/canary personas (Chrome 96, IE11)
    // are intentionally not in the rotation and are excluded here.
    use crate::fingerprint::tls_targets::FINGERPRINT_TARGETS;
    use crate::fingerprint::ROTATION_PROFILES;
    use std::collections::HashSet;

    // Measured real-browser JA4s. Safari is not a built-in target (no Apple-hardware
    // H2 capture on this fleet) but its TLS ClientHello was captured, so its JA4 is
    // part of the populated cluster.
    let mut populated: HashSet<&str> = FINGERPRINT_TARGETS.iter().map(|t| t.ja4).collect();
    populated.insert("t13d2014h2_a09f3c656075_2a6581477f52");

    for persona in ROTATION_PROFILES {
        let Some(tls) = profile_for_stealth_profile(*persona) else {
            // No TLS catalogue entry for this persona, skip only if it is genuinely
            // not browser-shaped; the None arm itself is worth surfacing elsewhere.
            continue;
        };

        let ja4 = compute_ja4_string(tls);
        assert!(
            populated.contains(ja4.as_str()),
            "{persona:?} ({}) emits JA4 {ja4} which does not collide with any populated \
             real-browser cluster, the persona is trackable",
            tls.name
        );
    }
}

#[test]
fn anti_uniqueness_set_rejects_a_distinctive_ja4() {
    // Negative twin for the population guard: an obviously alien JA4 must not be
    // mistaken for a populated browser cluster.
    use crate::fingerprint::tls_targets::FINGERPRINT_TARGETS;
    let populated: std::collections::HashSet<&str> =
        FINGERPRINT_TARGETS.iter().map(|t| t.ja4).collect();
    assert!(!populated.contains("t13d9999h2_deadbeefcafe_0123456789ab"));
}

#[test]
fn safari_18_profile_reproduces_the_measured_wire_fingerprint() {
    // RESOLVED (2026-06-13): the Safari TLS gap is closed with MEASURED data. The
    // prior `SAFARI_17` borrowed Chrome's TLS primitives (a placeholder that emitted
    // a matches-nothing `t13d03…` JA4); `SAFARI_18` now carries the real Safari-18
    // macOS ClientHello captured from the BoringSSL `StealthClient` (Safari18
    // emulation, whose TLS is browser-specific, validated by Chrome/Firefox
    // cipher-hashes matching guise in the live peet gate) via tls.peet.ws. This pins
    // that guise's own `compute_ja3`/`compute_ja4` over the profile reproduce the
    // measured wire values BYTE-FOR-BYTE, so the data is proven correct, not
    // hand-guessed. Captured values: oracles/live_peet_clienthellos_20260613.txt.
    assert_eq!(
        compute_ja3_hash(&client_hello_fields(&SAFARI_18)),
        "773906b0efdefa24a7f2b8eb6985bf37",
        "SAFARI_18 JA3 must reproduce the measured Safari-18 wire JA3 hash",
    );
    // JA4 `_a` (20 ciphers / 14 exts / h2) and the `_b` cipher-hash `a09f3c656075`
    // match the measured wire byte-for-byte, proving the cipher set is correct. The
    // `_c` ext+sigalg hash is guise's SPEC-CONFORMANT value: Safari's ClientHello
    // carries the RFC-7685 padding extension (0x0015), which the published FoxIO JA4
    // spec keeps in the sorted `_c` hash but tls.peet.ws drops, the SAME documented
    // divergence pinned for curl in `curl_ja4_follows_the_published_spec_padding_rule`.
    // So guise yields `_c=2a6581477f52` (padding kept); peet reported `_c=874d27d7ca63`
    // (padding dropped). guise follows the spec (matching Cloudflare/Akamai-class
    // detectors). Recorded, not "fixed".
    let ja4 = compute_ja4_string(&SAFARI_18);
    assert_eq!(
        ja4, "t13d2014h2_a09f3c656075_2a6581477f52",
        "SAFARI_18 JA4 (spec-conformant, padding kept) must reproduce; peet drops padding → 874d27d7ca63",
    );
    assert!(
        ja4.starts_with("t13d2014h2_a09f3c656075_"),
        "JA4 _a/_b (cipher set) must match the measured Safari-18 wire exactly",
    );
}

#[test]
fn safari_ios_18_profile_reproduces_the_measured_wire_fingerprint() {
    // RESOLVED (2026-06-13): the iOS Safari TLS gap is closed with MEASURED data.
    // The prior `SAFARI_IOS_17` borrowed Chrome's ciphers/sigalgs/curves + GREASE
    // (a placeholder no real Safari ever sent). The iPad-Safari-18 ClientHello was
    // captured from the BoringSSL `StealthClient` (`SafariIpad18` emulation) via
    // tls.peet.ws, and it is BYTE-FOR-BYTE IDENTICAL to the desktop macOS Safari-18
    // capture: Apple ships ONE coretls stack across macOS/iPadOS/iOS per Safari
    // major, so the TLS layer does not encode the OS. `SAFARI_IOS_18` therefore
    // reuses the measured `SAFARI_18` wire slices (no fabrication, no duplication)
    // and only differs in `name`. Captured: oracles/live_peet_clienthellos_20260613.txt.
    assert_eq!(
        compute_ja3_hash(&client_hello_fields(&SAFARI_IOS_18)),
        "773906b0efdefa24a7f2b8eb6985bf37",
        "SAFARI_IOS_18 JA3 must reproduce the measured iPad-Safari-18 wire JA3 hash",
    );
    // Same spec-conformant JA4 as desktop Safari-18 (padding ext 0x0015 kept; peet
    // drops it → reports `_c=874d27d7ca63`). The iOS persona and the macOS persona
    // are TLS-indistinguishable on the wire (that is the measured truth, not a bug).
    assert_eq!(
        compute_ja4_string(&SAFARI_IOS_18),
        "t13d2014h2_a09f3c656075_2a6581477f52",
        "SAFARI_IOS_18 JA4 must reproduce the measured Safari-18 coretls wire (padding kept)",
    );
    // Lock the measured coincidence: iOS and macOS Safari-18 share Apple coretls, so
    // every wire field is identical. If a future edit diverges them WITHOUT a fresh
    // per-OS capture proving Apple split the stack, this catches the fabrication.
    assert_eq!(SAFARI_IOS_18.cipher_suites, SAFARI_18.cipher_suites);
    assert_eq!(SAFARI_IOS_18.extensions, SAFARI_18.extensions);
    assert_eq!(SAFARI_IOS_18.elliptic_curves, SAFARI_18.elliptic_curves);
    assert_eq!(
        SAFARI_IOS_18.signature_algorithms,
        SAFARI_18.signature_algorithms
    );
    assert_eq!(SAFARI_IOS_18.include_grease, SAFARI_18.include_grease);
    // …but the NAME must stay iOS-coherent (an iPhone persona must never report a
    // macOS TLS profile name), so the two profiles are not wholly interchangeable.
    assert_eq!(SAFARI_IOS_18.name, "Safari 18 / iOS");
    assert_ne!(SAFARI_IOS_18.name, SAFARI_18.name);
}

#[test]
fn ja4_string_delegates_to_shared_ja4_renderer() {
    let profile = profile_for("chrome").unwrap();
    let fields = client_hello_fields(profile);
    assert_eq!(
        compute_ja4_string(profile),
        crate::fingerprint::ja3::compute_ja4(&fields)
    );
}

#[test]
fn browser_profiles_advertise_h2_then_http11_alpn() {
    // G055: real Chrome/Firefox/Safari offer ALPN exactly `h2, http/1.1` in that
    // order. An h2-only or reordered ALPN is a transport tell.
    for name in ["chrome", "firefox", "safari"] {
        let profile = profile_for(name).unwrap_or_else(|| panic!("{name} profile must ship"));
        assert_eq!(
            profile.alpn_protocols,
            &["h2", "http/1.1"],
            "{name} ALPN must be h2 then http/1.1"
        );
    }
}

#[test]
fn firefox_linux_profile_is_the_measured_ff150_modal_wire_shape() {
    // G005/G049/G050: the FirefoxLinux persona's pure-TLS catalogue entry is the
    // EXACT measured FF-150/Linux ClientHello, so its computed JA3 and JA4 equal
    // the real values stock Firefox emits, the modal value a huge population of
    // real users share, NOT a distinctive (trackable) shape. These are the same
    // bytes proven against the wire in `ja3::tests::ja3_and_ja4_for_firefox_150_*`;
    // asserting them here proves the *catalogue* (not just a test fixture) carries
    // the real shape.
    let ff = profile_for_stealth_profile(StealthProfile::FirefoxLinux)
        .expect("FirefoxLinux must map to a TLS profile");
    assert_eq!(ff.name, "Firefox 150");
    let fields = client_hello_fields(ff);
    assert_eq!(
        compute_ja3_hash(&fields),
        "0e76c7e9d06fa0e211b1827687dd8f43",
        "FirefoxLinux JA3 must reproduce the measured modal FF-150 value"
    );
    assert_eq!(
        compute_ja4_string(ff),
        "t13d1717h2_5b57614c22b0_e6dcd7ae0a9e",
        "FirefoxLinux JA4 must reproduce the measured modal FF-150 value"
    );
}

#[test]
fn both_desktop_firefox_personas_share_the_os_independent_ff150_tls() {
    // Coherence fix: Firefox's NSS ClientHello is OS-independent + version-stable,
    // so FirefoxLinux AND FirefoxWindows must resolve to the SAME measured FF-150
    // shape, not two divergent profiles, and emphatically not the EOL FF-115-ESR
    // shape FirefoxWindows used to map to (a stale Firefox/133 UA paired with a
    // 115-ESR ClientHello was the incoherence this closes; the persona UA is now
    // Firefox/150, matching this profile's major). A real per-OS TLS split would
    // itself be a tell, since stock Firefox does not produce one.
    let linux = profile_for_stealth_profile(StealthProfile::FirefoxLinux).unwrap();
    let windows = profile_for_stealth_profile(StealthProfile::FirefoxWindows).unwrap();
    assert_eq!(windows.name, "Firefox 150");
    assert_eq!(
        compute_ja3_hash(&client_hello_fields(linux)),
        compute_ja3_hash(&client_hello_fields(windows)),
        "both desktop-Firefox personas must share one OS-independent JA3"
    );
    assert_eq!(
        compute_ja4_string(linux),
        compute_ja4_string(windows),
        "both desktop-Firefox personas must share one OS-independent JA4"
    );
}

#[test]
fn firefox_persona_ua_major_matches_its_tls_profile_version() {
    // The invariant the stale Firefox/133 UA was silently violating: a persona's
    // User-Agent major MUST equal the major of the TLS profile its HTTP-client
    // emits, or a JA3+UA correlation check sees a Firefox/<x> UA shipping a
    // Firefox/<y> ClientHello. Both desktop-Firefox personas map to FIREFOX_150
    // and now carry a Firefox/150 UA, so the pair is coherent. Pinned here so a
    // future bump that moves only the UA or only the TLS shape fails loudly
    // instead of re-opening the mismatch.
    for profile in [StealthProfile::FirefoxLinux, StealthProfile::FirefoxWindows] {
        let ua = crate::fingerprint::profile_user_agent(profile);
        let ua_major = crate::fingerprint::user_agent_facts(ua)
            .browser_major_version
            .expect("Firefox persona UA carries a major version");
        let tls = profile_for_stealth_profile(profile).expect("Firefox persona has a TLS profile");
        // The profile name is "Firefox <major>"; its trailing token is the version.
        let tls_major: u32 = tls
            .name
            .rsplit(' ')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("TLS profile name {:?} lacks a trailing version", tls.name));
        assert_eq!(
            ua_major, tls_major,
            "{profile:?}: UA major {ua_major} (from {ua:?}) must equal TLS profile major \
             {tls_major} (from {:?})",
            tls.name
        );
    }
}

#[test]
fn every_rotation_persona_resolves_to_a_complete_coherent_stack() {
    // X010/X011, atomic rotation. Every persona the deterministic cycle can land
    // on MUST resolve a COMPLETE stack with no missing or stale layer: a non-empty
    // UA, a measured TLS profile, and a TCP stack whose OS matches the UA's OS
    // all describing ONE identity. A rotation persona lacking a TLS profile would
    // silently keep the PREVIOUS persona's JA3/JA4 after a rotate (a cross-layer
    // split a JA3+UA correlation flags); one with a UA-OS != TCP-OS would ship a
    // mismatched SYN signature. Pinned across the full rotation set so neither can
    // be introduced by adding a persona to the cycle.
    use crate::fingerprint::{profile_os_network_stack, profile_user_agent, user_agent_facts};
    for &persona in crate::rotation::profiles() {
        let ua = profile_user_agent(persona);
        assert!(
            !ua.is_empty(),
            "{persona:?}: rotation persona has an empty UA"
        );
        assert!(
            profile_for_stealth_profile(persona).is_some(),
            "{persona:?}: rotation persona has NO TLS profile, a rotate to it would leave the \
             prior persona's JA3/JA4 in place (a stale-layer cross-fingerprint split)"
        );
        let ua_os = user_agent_facts(ua).platform;
        let stack = profile_os_network_stack(persona);
        assert_eq!(
            ua_os, stack.os,
            "{persona:?}: rotation persona UA-OS {ua_os:?} (from {ua:?}) != TCP-stack OS {:?}",
            stack.os
        );
    }
}

#[test]
fn firefox_151_is_the_measured_current_stable_shape() {
    // Real stock Firefox 151 captured live 2026-06-12 (tls.peet.ws). It is the
    // FF-150 shape with exactly one cipher removed. Firefox dropped 0xc009
    // (ECDHE_ECDSA_AES_128_CBC_SHA) at 151. Pin the measured JA3/JA4 so the
    // catalogue's current-stable entry stays byte-accurate, and assert the
    // FF-150→151 relationship explicitly (only ciphers move; ext/group shape, and
    // therefore the JA4 _c ext-hash, are invariant).
    let ff151 = profiles()
        .iter()
        .find(|p| p.name == "Firefox 151")
        .expect("Firefox 151 profile must ship");
    let ff150 = profiles()
        .iter()
        .find(|p| p.name == "Firefox 150")
        .expect("Firefox 150 profile must ship");
    assert_eq!(
        compute_ja3_hash(&client_hello_fields(ff151)),
        "f19d54c853fffdd9eeab77ae607448e9",
        "FF-151 JA3 must reproduce the measured stock-Firefox-151 value"
    );
    assert_eq!(
        compute_ja4_string(ff151),
        "t13d1617h2_86a278354501_e6dcd7ae0a9e",
        "FF-151 JA4 must reproduce the measured stock-Firefox-151 value"
    );
    // The single-cipher 150→151 delta: 0xc009 dropped, 17→16, nothing else.
    assert_eq!(ff151.cipher_suites.len(), 16);
    assert_eq!(ff150.cipher_suites.len(), 17);
    assert!(
        !ff151.cipher_suites.contains(&0xc009),
        "FF-151 must NOT offer the dropped 0xc009 cipher"
    );
    let ff150_minus_c009: Vec<u16> = ff150
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| *c != 0xc009)
        .collect();
    assert_eq!(
        ff151.cipher_suites,
        ff150_minus_c009.as_slice(),
        "FF-151 ciphers must be exactly FF-150's minus 0xc009 (same order)"
    );
    // Extension/group/sigalg shape is invariant across 150→151, so the JA4 _c
    // ext-hash is identical (the divergence is confined to ciphers / JA4 _a+_b).
    assert_eq!(ff151.extensions, ff150.extensions);
    assert_eq!(ff151.elliptic_curves, ff150.elliptic_curves);
    let c151 = compute_ja4_string(ff151);
    let c150 = compute_ja4_string(ff150);
    assert_eq!(
        &c151[c151.rfind('_').unwrap()..],
        &c150[c150.rfind('_').unwrap()..],
        "FF-150 and FF-151 must share one JA4 _c ext-hash (ext/sigalg shape unchanged)"
    );
}

#[test]
fn chrome_146_profile_reproduces_the_measured_stable_ja4() {
    // Real stock Chrome 146 captured live 2026-06-12. The JA4 is the stable,
    // cross-connection fingerprint (Chrome randomizes ext order, so the JA3 is a
    // sampled order self-checksummed by `expected_ja3`). `compute_ja4` over the
    // measured cipher/extension/sigalg fields must reproduce the real value
    // byte-for-byte, the catalogue's first byte-accurate Chrome (the older
    // CHROME_122/120 carry a 3-cipher placeholder).
    let chrome = profiles()
        .iter()
        .find(|p| p.name == "Chrome 146")
        .expect("Chrome 146 profile must ship");
    assert_eq!(
        compute_ja4_string(chrome),
        "t13d1517h2_8daaf6152771_b6f405a00624",
        "Chrome 146 JA4 must reproduce the measured stable value"
    );
    assert_eq!(
        compute_ja3_hash(&client_hello_fields(chrome)),
        "9c713794cc9790422a2bc435e7038fbf",
        "Chrome 146 JA3 must self-checksum to the sampled-order md5"
    );
    assert_eq!(chrome.cipher_suites.len(), 15);
    assert_eq!(chrome.extensions.len(), 17);
    // The modern Chrome extensions a placeholder dropped: ECH, ALPS-0x44cd, PSK.
    for ext in [0xfe0du16, 0x44cd, 0x0029] {
        assert!(
            chrome.extensions.contains(&ext),
            "Chrome 146 must advertise {ext:#06x}"
        );
    }
    // Leads with the PQ hybrid group, and emits GREASE on the wire.
    assert_eq!(chrome.elliptic_curves.first(), Some(&0x11ecu16));
    assert!(chrome.include_grease, "Chrome sends GREASE");
    // profile_for("chrome") now resolves the MEASURED Chrome, not the placeholder.
    assert_eq!(profile_for("chrome").unwrap().name, "Chrome 146");
}

fn curl_profile() -> &'static TlsProfile {
    profiles()
        .iter()
        .find(|p| p.name == "curl 8 / OpenSSL 3")
        .expect("curl 8 / OpenSSL 3 profile must ship")
}

#[test]
fn curl_8_openssl_is_the_measured_wire_shape() {
    // The curl profile is the byte-accurate measured `curl 8.5.0 (OpenSSL/3.0.13)`
    // ClientHello captured live 2026-06-12 against tls.peet.ws, not an
    // approximation. Pin the EXACT canonical JA3 string (every cipher/extension/
    // group/point-format, in wire order) and its MD5, so any later field edit that
    // drifts from the real curl wire shape fails loudly.
    let curl = curl_profile();
    let measured_ja3 = "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-16-22-23-49-13-43-45-51-21,29-23-30-25-24-256-257-258-259-260,0-1-2";
    assert_eq!(
        compute_ja3_string(curl),
        measured_ja3,
        "curl JA3 string drifted from the measured curl 8.5/OpenSSL 3 wire shape"
    );
    assert_eq!(
        compute_ja3_hash(&client_hello_fields(curl)),
        "0149f47eabf9a20d0893e2a44e5a6323",
        "curl JA3 hash must equal the value tls.peet.ws computed for this curl build"
    );
    // 31 ciphers, 12 extensions (incl. RFC-7685 padding 0x0015), 10 groups (5
    // named + 5 FFDHE) (the OpenSSL default offer, distinct from any browser).
    assert_eq!(curl.cipher_suites.len(), 31);
    assert_eq!(curl.extensions.len(), 12);
    assert_eq!(curl.elliptic_curves.len(), 10);
    assert!(
        curl.extensions.contains(&0x0015),
        "curl sends RFC-7685 padding"
    );
    assert_eq!(curl.ec_point_formats, &[0x00, 0x01, 0x02]);
}

#[test]
fn curl_ja4_follows_the_published_spec_padding_rule() {
    // Documented oracle divergence (proven empirically from the same capture): the
    // curl ClientHello carries the padding extension (0x0015). The published FoxIO
    // JA4 spec + threatrelay reference KEEP padding in the sorted JA4_c hash
    // (excluding only SNI 0x0000 and ALPN 0x0010), so our spec-conformant
    // `compute_ja4` yields `…_b26ce05bbdd6`. tls.peet.ws instead drops padding and
    // reports `…_375ca2c5e164` (the two differ ONLY in the _c ext-hash; the _a
    // header and _b cipher-hash are identical). guise follows the published spec so
    // it matches spec-conformant detectors (Cloudflare/Akamai-class). This test
    // pins both values so the divergence stays a recorded fact, not a silent drift.
    let curl = curl_profile();
    let spec_ja4 = compute_ja4_string(curl);
    assert_eq!(
        spec_ja4, "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6",
        "curl JA4 must be the spec-conformant value (padding retained in JA4_c)"
    );
    let peet_ja4 = "t13d3112h2_e8f1e7e78f70_375ca2c5e164";
    assert_ne!(
        spec_ja4, peet_ja4,
        "spec JA4 and peet JA4 must differ, they disagree on padding in JA4_c"
    );
    // The divergence is confined to the _c ext-hash; _a + _b are shared.
    let spec_head = &spec_ja4[..spec_ja4.rfind('_').unwrap()];
    let peet_head = &peet_ja4[..peet_ja4.rfind('_').unwrap()];
    assert_eq!(
        spec_head, peet_head,
        "only the JA4_c ext-hash may differ between the spec and peet renderings"
    );
}

#[test]
fn python_requests_shares_curl_openssl3_ja3_but_differs_in_alpn_ja4() {
    // Measured finding (live 2026-06-12): requests/urllib3 and curl both link
    // OpenSSL 3.0.13 and emit the byte-identical default ClientHello, so they share
    // JA3 `0149f47e…`: JA3 alone cannot tell them apart. They diverge ONLY in
    // ALPN (urllib3 is http/1.1-only), which surfaces in the JA4 ALPN digit:
    // curl `…h2`, python `…h1`. The JA4 `_b` cipher-hash and `_c` ext-hash stay
    // identical (same suites + extensions + sigalgs).
    let curl = curl_profile();
    let py = profiles()
        .iter()
        .find(|p| p.name.starts_with("Python requests"))
        .expect("python requests profile must ship");
    assert_eq!(
        compute_ja3_string(py),
        compute_ja3_string(curl),
        "python-requests and curl must share the OpenSSL-3 JA3 string"
    );
    assert_eq!(
        compute_ja3_hash(&client_hello_fields(py)),
        "0149f47eabf9a20d0893e2a44e5a6323"
    );
    // Slices are reused, not duplicated.
    assert_eq!(py.cipher_suites, curl.cipher_suites);
    assert_eq!(py.extensions, curl.extensions);
    assert_eq!(py.signature_algorithms, curl.signature_algorithms);
    assert_eq!(py.elliptic_curves, curl.elliptic_curves);
    // ALPN is the sole discriminator.
    assert_eq!(py.alpn_protocols, &["http/1.1"]);
    assert!(curl.alpn_protocols.contains(&"h2"));
    let pj = compute_ja4_string(py);
    let cj = compute_ja4_string(curl);
    assert!(
        pj.starts_with("t13d3112h1_"),
        "python JA4 must carry h1: {pj}"
    );
    assert!(
        cj.starts_with("t13d3112h2_"),
        "curl JA4 must carry h2: {cj}"
    );
    assert_eq!(
        &pj[pj.find('_').unwrap()..],
        &cj[cj.find('_').unwrap()..],
        "python and curl JA4 must share _b and _c (only the ALPN digit differs)"
    );
}

#[test]
fn firefox_extension_order_is_ff_authentic_and_unlike_chrome() {
    // G007/G058: extension ORDER is the JA3 discriminator. Pin the golden measured
    // FF-150 extension sequence byte-for-byte (a future field edit must update this
    // golden deliberately), and assert it is NOT Chrome's order, a FF persona
    // emitting Chrome's extension layout is an instant cross-family tell.
    let ff = profile_for_stealth_profile(StealthProfile::FirefoxLinux).unwrap();
    let golden: &[u16] = &[
        0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x0022, 0x0012, 0x0033, 0x002b,
        0x000d, 0x002d, 0x001c, 0x001b, 0xfe0d, 0x0029,
    ];
    assert_eq!(
        ff.extensions, golden,
        "FF-150 extension order drifted from the measured golden table"
    );
    let chrome = profile_for("chrome").unwrap();
    assert_ne!(
        ff.extensions, chrome.extensions,
        "Firefox must not share Chrome's extension order"
    );
}

#[test]
fn firefox_150_carries_the_modern_tls_extensions_without_grease() {
    // G056/G057/G008: the real FF-150 ClientHello advertises modern extensions a
    // simplified placeholder dropped. Their PRESENCE is part of the FF fingerprint
    //: a FF persona missing them is distinguishable from stock Firefox.
    let ff = profile_for_stealth_profile(StealthProfile::FirefoxLinux).unwrap();
    for (ext, label) in [
        (0x0022u16, "delegated_credentials"), // G057
        (0x001c, "record_size_limit"),        // G057
        (0x001b, "compress_certificate"),     // G056
        (0xfe0d, "encrypted_client_hello"),   // G008
        (0x0029, "pre_shared_key"),
    ] {
        assert!(
            ff.extensions.contains(&ext),
            "FF-150 must advertise {label} ({ext:#06x})"
        );
    }
    // Firefox sends NO GREASE in its ClientHello (unlike Chrome); none may appear
    // in any of its three GREASE-eligible lists.
    for &ext in ff.extensions {
        assert!(
            !GREASE_VALUES.contains(&ext),
            "Firefox must carry no GREASE extension, found {ext:#06x}"
        );
    }
    assert!(
        !ff.include_grease,
        "Firefox profiles must not inject GREASE"
    );
}

#[test]
fn firefox_150_offers_the_post_quantum_hybrid_group_first() {
    // Modern Firefox offers the X25519MLKEM768 post-quantum hybrid (0x11ec) as the
    // FIRST supported group. A FF persona lacking it, or ordering it elsewhere
    // diverges from current stock FF, where the PQ hybrid is now a positive signal.
    let ff = profile_for_stealth_profile(StealthProfile::FirefoxLinux).unwrap();
    assert_eq!(
        ff.elliptic_curves.first(),
        Some(&0x11ec),
        "FF-150 must lead supported_groups with X25519MLKEM768 (0x11ec)"
    );
}

#[test]
fn chrome_grease_is_randomized_not_a_fixed_constant() {
    // G006 (the slice the other GREASE tests don't cover): real Chrome varies its
    // GREASE value per handshake, a PINNED GREASE (e.g. always 0x0a0a) is itself a
    // trackable tell. Drawing the cipher-slot GREASE 64 times must yield more than
    // one distinct value (P(all 64 identical) ≈ 16^-63, never in practice),
    // proving the slot is randomized, not a fixed constant; every drawn value must
    // still be a valid GREASE code. Guards against someone replacing `random_grease`
    // with a constant to make a test deterministic.
    let chrome = profile_for("chrome").unwrap();
    assert!(chrome.include_grease);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..64 {
        let g = build_cipher_suites(chrome)[0];
        assert!(
            GREASE_VALUES.contains(&g),
            "slot 0 must be GREASE, got {g:#06x}"
        );
        seen.insert(g);
    }
    assert!(
        seen.len() > 1,
        "GREASE must be randomized across handshakes, not pinned to {seen:?}"
    );
}

#[cfg(feature = "http")]
#[test]
fn default_tls_profile_family_matches_bundle_browser_family() {
    // G090: the TLS profile attached to a bundle must claim the same browser
    // family as the bundle's browser persona. This is the positive twin of the
    // cross-layer mismatch gate tested elsewhere.
    use crate::fingerprint::{
        bundle::ProfileBundle, profile_user_agent, user_agent_facts, UserAgentBrowser,
        ROTATION_PROFILES,
    };

    for profile in ROTATION_PROFILES {
        let bundle = ProfileBundle::for_browser(*profile);
        let tls_family = impersonate_profile_family(bundle.tls)
            .expect("rotation-profile TLS must have a classified family");
        let browser_family = match user_agent_facts(profile_user_agent(*profile)).browser {
            // Chromium-derived personas (Chrome, Edge, Brave, Opera, Samsung) all
            // resolve to a Chromium-family TLS ClientHello.
            UserAgentBrowser::Chrome
            | UserAgentBrowser::Edge
            | UserAgentBrowser::Opera
            | UserAgentBrowser::SamsungInternet => "chrome",
            UserAgentBrowser::Firefox => "firefox",
            UserAgentBrowser::Safari => "safari",
            other => panic!("rotation profile {profile:?} has unexpected browser family {other:?}"),
        };
        assert_eq!(
            tls_family, browser_family,
            "{profile:?} bundle browser family {browser_family} does not match TLS family {tls_family}"
        );
    }
}
