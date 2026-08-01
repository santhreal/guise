use super::*;

// ── Transport coherence: the TCP/IP layer below HTTP/2 ────────────────────────

#[test]
fn transport_coherence_bundles_all_three_layers_coherently() {
    // FirefoxWindows: TCP/IP stack says Windows (TTL 128), HTTP/2 + header order
    // say the Firefox family. All three must resolve together.
    let tc = transport_coherence_for_profile(StealthProfile::FirefoxWindows)
        .expect("FirefoxWindows has a full transport profile");
    assert_eq!(tc.network.os, UserAgentPlatform::Windows);
    assert_eq!(tc.network.initial_ttl, 128);
    assert_eq!(tc.h2.family, "firefox");
    assert_eq!(tc.header_order.family, "firefox");

    // FirefoxLinux shares the Firefox HTTP layers but a Linux TCP/IP stack.
    let lin = transport_coherence_for_profile(StealthProfile::FirefoxLinux)
        .expect("FirefoxLinux has a full transport profile");
    assert_eq!(lin.network.initial_ttl, 64);
    assert_eq!(lin.h2.family, "firefox");
    // Same browser family, different OS stack, exactly the layered picture the
    // bundle exists to expose.
    assert_eq!(lin.h2, tc.h2);
    assert_ne!(lin.network, tc.network);
}

#[test]
fn transport_coherence_network_os_matches_every_profiles_claimed_os() {
    for profile in crate::fingerprint::ALL_PROFILES {
        if let Some(tc) = transport_coherence_for_profile(*profile) {
            assert_eq!(
                tc.network.os,
                crate::fingerprint::profile_platform(*profile),
                "{profile:?}: transport network OS disagrees with claimed platform"
            );
        }
    }
}

#[test]
fn transport_coherence_absent_for_personas_without_http_profile() {
    // IE11 has no modeled HTTP/2 + header-order profile, matching pair_for_profile.
    assert!(transport_coherence_for_profile(StealthProfile::Ie11Windows).is_none());
    assert!(pair_for_profile(StealthProfile::Ie11Windows).is_none());
}

#[test]
fn transport_coherence_exposes_the_foxio_windows_ja4t_end_to_end() {
    // End-to-end wiring: persona → resolved transport bundle → JA4T. A Windows
    // persona's transport layer must present FoxIO's published Windows-11
    // reference `64240_2-1-3-1-1-4_1460_8`, proving the whole path (persona OS →
    // TCP stack → JA4+ TCP-client fingerprint) is wired, not just the leaf method.
    let win = transport_coherence_for_profile(StealthProfile::FirefoxWindows)
        .expect("FirefoxWindows has a full transport profile");
    assert_eq!(win.ja4t().unwrap(), "64240_2-1-3-1-1-4_1460_8");

    // An autotuned-window persona wildcards the window field only; the concrete
    // option/MSS/wscale tail still distinguishes it from the Windows stack.
    let lin = transport_coherence_for_profile(StealthProfile::FirefoxLinux)
        .expect("FirefoxLinux has a full transport profile");
    assert_eq!(lin.ja4t().unwrap(), "*_2-4-8-1-3_1460_7");
    assert_ne!(win.ja4t().unwrap(), lin.ja4t().unwrap());
}

#[test]
fn host_platform_agrees_with_compiled_target_os() {
    let expected = match std::env::consts::OS {
        "linux" => UserAgentPlatform::Linux,
        "macos" => UserAgentPlatform::MacOs,
        "windows" => UserAgentPlatform::Windows,
        "android" => UserAgentPlatform::Android,
        "ios" => UserAgentPlatform::Ios,
        _ => UserAgentPlatform::Unknown,
    };
    assert_eq!(host_platform(), expected);

    // A known host OS has a modeled initial TTL; an unmodeled one does not.
    match host_platform() {
        UserAgentPlatform::Unknown => assert_eq!(host_initial_ttl(), None),
        _ => assert!(host_initial_ttl().is_some()),
    }
}

#[test]
fn persona_host_network_coherence_is_host_relative_not_hardcoded() {
    // Host-independent by construction (cf. the select_backend host-dependency
    // trap): the expected verdict is derived from the host this test runs on, so
    // it holds on Linux, macOS, and Windows CI alike.
    let host = host_platform();

    // A persona claiming the same OS family as the host is coherent.
    let same_os_persona = match host {
        UserAgentPlatform::Linux => Some(StealthProfile::FirefoxLinux),
        UserAgentPlatform::Windows => Some(StealthProfile::FirefoxWindows),
        UserAgentPlatform::MacOs => Some(StealthProfile::SafariMacStable),
        UserAgentPlatform::Android => Some(StealthProfile::ChromeAndroid),
        UserAgentPlatform::Ios => Some(StealthProfile::SafariIphone),
        UserAgentPlatform::Unknown => None,
    };

    // A persona whose claimed OS sits in a different TTL band than the host
    // Windows (128) vs any Unix-family host (64), or vice-versa.
    let cross_band_persona = match host {
        UserAgentPlatform::Windows => Some(StealthProfile::FirefoxLinux),
        UserAgentPlatform::Linux
        | UserAgentPlatform::MacOs
        | UserAgentPlatform::Android
        | UserAgentPlatform::Ios => Some(StealthProfile::FirefoxWindows),
        UserAgentPlatform::Unknown => None,
    };

    match same_os_persona {
        Some(profile) => assert!(
            persona_host_network_coherence(profile).is_coherent(),
            "{host:?} host: a same-OS persona must be transport-coherent"
        ),
        None => assert_eq!(
            persona_host_network_coherence(StealthProfile::FirefoxLinux),
            NetworkOsCoherence::Unknown,
            "unmodeled host OS must yield Unknown, never a false verdict"
        ),
    }

    if let Some(profile) = cross_band_persona {
        let verdict = persona_host_network_coherence(profile);
        assert!(
            !verdict.is_coherent(),
            "{host:?} host: a cross-band persona's L2 stack must be flagged ({verdict:?})"
        );
    }
}

// ── G022 coherence gate: one persona identity across every transport layer ────

#[test]
fn every_persona_transport_layer_agrees_on_one_identity() {
    // The regression guard: every shipped persona's TCP-OS, HTTP/2 family, and
    // header-order family must agree with its UA's (browser, OS). A future
    // persona wired to the wrong family trips here instead of leaking in prod.
    for profile in crate::fingerprint::ALL_PROFILES {
        assert_eq!(
            persona_transport_coherence(*profile),
            Ok(()),
            "{profile:?}: transport layers disagree on one identity"
        );
    }
}

#[test]
fn every_persona_passes_full_stack_coherence() {
    // X007 / X045 regression guard: every shipped persona must be coherent from
    // the JS surface (UA↔platform↔WebGL↔brands) ALL THE WAY DOWN to the wire
    // (UA-OS==TCP-OS, HTTP/2↔header↔browser↔TLS families) in ONE check. A future
    // persona wired incoherent on EITHER half trips here instead of leaking.
    for profile in crate::fingerprint::ALL_PROFILES {
        persona_full_stack_coherence(*profile)
            .unwrap_or_else(|e| panic!("{profile:?} is full-stack incoherent: {e}"));
    }
}

#[test]
fn full_stack_gate_surfaces_a_browser_half_failure() {
    // The unified gate must PROPAGATE a browser-half incoherence, not swallow it
    // (Law 10): break one JS axis (platform) on an otherwise-coherent persona and
    // confirm the gate returns Browser(..) carrying the specific message, proof
    // the browser half is actually wired into the unified check, not just the
    // transport half.
    let mut ov = crate::fingerprint::profile_to_overrides(&StealthProfile::FirefoxLinux);
    ov.platform = "Win32".into();
    match full_stack_coherence_of(StealthProfile::FirefoxLinux, &ov) {
        Err(PersonaIncoherence::Browser(msg)) => assert!(
            msg.contains("Linux-based but platform is"),
            "expected the Linux platform mismatch surfaced through the unified gate, got: {msg}"
        ),
        other => panic!("expected a Browser-half incoherence, got {other:?}"),
    }
}

#[test]
fn full_stack_gate_passes_when_both_halves_agree() {
    // Positive twin of the surfacing test, on the same seam: a persona's REAL
    // overrides (unbroken) pass (the gate isn't rejecting everything).
    let ov = crate::fingerprint::profile_to_overrides(&StealthProfile::FirefoxLinux);
    assert_eq!(
        full_stack_coherence_of(StealthProfile::FirefoxLinux, &ov),
        Ok(())
    );
}

#[test]
fn self_probe_coherent_on_own_wire_and_flags_cross_os_for_every_persona() {
    // Exhaustive over the whole rotation set: a persona fed its OWN expected wire
    // (TTL in its OS band + its family Akamai) is Coherent; the same persona on a
    // different-OS egress is flagged at the TTL layer. Adding a persona wired to
    // the wrong stack trips this instead of leaking.
    for profile in crate::fingerprint::ALL_PROFILES {
        let stack = crate::fingerprint::profile_os_network_stack(*profile);
        let own_akamai = pair_for_profile(*profile).map(|(_, h2)| h2.akamai_fingerprint());

        let own = WireCapture {
            observed_ttl: Some(stack.initial_ttl),
            akamai_fingerprint: own_akamai.clone(),
            observed_ja4t: None,
        };
        assert_eq!(
            persona_wire_self_probe(*profile, &own),
            WireSelfProbe::Coherent,
            "{profile:?}: own expected wire must be coherent"
        );

        let wrong_initial = if stack.initial_ttl == 64 { 128 } else { 64 };
        let cross_os = WireCapture {
            observed_ttl: Some(wrong_initial),
            akamai_fingerprint: own_akamai,
            observed_ja4t: None,
        };
        match persona_wire_self_probe(*profile, &cross_os) {
            WireSelfProbe::Incoherent(mismatches) => assert!(
                mismatches.iter().any(|m| matches!(
                    m,
                    WireLayerMismatch::Ttl { observed_initial_ttl, .. }
                        if *observed_initial_ttl == wrong_initial
                )),
                "{profile:?}: a cross-OS egress TTL was not flagged"
            ),
            other => panic!("{profile:?}: expected a TTL mismatch, got {other:?}"),
        }
    }
}

#[test]
fn self_probe_flags_foreign_engine_akamai_for_every_modeled_persona() {
    // For every persona with a modeled H2 profile, a wire showing a DIFFERENT
    // engine's Akamai fingerprint (TTL held coherent to isolate the H2 layer) is
    // flagged (the "persona says X, the H2 wire says Y" engine mismatch).
    for profile in crate::fingerprint::ALL_PROFILES {
        let Some((_, own_h2)) = pair_for_profile(*profile) else {
            continue;
        };
        let foreign = [CHROME_H2, FIREFOX_H2, SAFARI_H2]
            .into_iter()
            .find(|h2| h2.family != own_h2.family)
            .expect("three distinct H2 families ship");
        let stack = crate::fingerprint::profile_os_network_stack(*profile);
        let capture = WireCapture {
            observed_ttl: Some(stack.initial_ttl),
            akamai_fingerprint: Some(foreign.akamai_fingerprint()),
            observed_ja4t: None,
        };
        match persona_wire_self_probe(*profile, &capture) {
            WireSelfProbe::Incoherent(mismatches) => assert!(
                mismatches
                    .iter()
                    .any(|m| matches!(m, WireLayerMismatch::Akamai { .. })),
                "{profile:?}: a foreign-engine Akamai was not flagged"
            ),
            other => panic!("{profile:?}: expected an Akamai mismatch, got {other:?}"),
        }
    }
}

#[test]
fn transport_family_folds_chromium_brands_and_rejects_ie() {
    assert_eq!(
        transport_family_for_browser(UserAgentBrowser::Chrome),
        Some("chrome")
    );
    assert_eq!(
        transport_family_for_browser(UserAgentBrowser::Edge),
        Some("chrome")
    );
    assert_eq!(
        transport_family_for_browser(UserAgentBrowser::Opera),
        Some("chrome")
    );
    assert_eq!(
        transport_family_for_browser(UserAgentBrowser::SamsungInternet),
        Some("chrome")
    );
    assert_eq!(
        transport_family_for_browser(UserAgentBrowser::Firefox),
        Some("firefox")
    );
    assert_eq!(
        transport_family_for_browser(UserAgentBrowser::Safari),
        Some("safari")
    );
    // No modeled transport profile → None, never a wrong-family guess.
    assert_eq!(
        transport_family_for_browser(UserAgentBrowser::InternetExplorer),
        None
    );
    assert_eq!(
        transport_family_for_browser(UserAgentBrowser::Unknown),
        None
    );
}

#[cfg(feature = "http")]
#[test]
fn every_personas_tls_family_agrees_with_its_http_family() {
    // G062: the default wire-impersonation family must match the HTTP family for
    // every persona that has both. Catches a persona wired to the wrong TLS
    // identity (e.g. a Firefox UA defaulting to Chrome's JA3).
    use crate::fingerprint::tls_profiles::{
        default_impersonate_profile_for_stealth_profile, impersonate_profile_family,
    };
    for profile in crate::fingerprint::ALL_PROFILES {
        let Some((_, h2)) = pair_for_profile(*profile) else {
            continue;
        };
        let tls = default_impersonate_profile_for_stealth_profile(*profile);
        if let Some(tls_family) = impersonate_profile_family(tls) {
            assert_eq!(
                tls_family, h2.family,
                "{profile:?}: TLS family {tls_family} != HTTP family {}",
                h2.family
            );
        }
    }
}

#[cfg(feature = "http")]
#[test]
fn impersonate_profile_family_classifies_browsers_and_rejects_okhttp() {
    use crate::fingerprint::tls_profiles::impersonate_profile_family;
    use scanclient::tls_impersonate::ImpersonateProfile;
    assert_eq!(
        impersonate_profile_family(ImpersonateProfile::Firefox133),
        Some("firefox")
    );
    assert_eq!(
        impersonate_profile_family(ImpersonateProfile::Chrome131),
        Some("chrome")
    );
    assert_eq!(
        impersonate_profile_family(ImpersonateProfile::Edge131),
        Some("chrome")
    );
    assert_eq!(
        impersonate_profile_family(ImpersonateProfile::Safari18),
        Some("safari")
    );
    // The mobile iPad-Safari emulation is the same browser family, an iPhone/iPad
    // persona's TLS layer must cross-check as "safari", not fall through to None
    // (which would silently disable the TLS-vs-UA family coherence check for it).
    assert_eq!(
        impersonate_profile_family(ImpersonateProfile::SafariIpad18),
        Some("safari")
    );
    // A non-browser client has no browser family (never a wrong guess).
    assert_eq!(
        impersonate_profile_family(ImpersonateProfile::OkHttp5),
        None
    );
}

#[test]
fn ie11_persona_is_coherent_with_no_http_layers_to_cross_check() {
    // IE11 has a TCP stack (Windows) but no HTTP/2 + header-order profile, so the
    // gate can only check the TCP layer (which is self-consistent).
    assert_eq!(
        persona_transport_coherence(StealthProfile::Ie11Windows),
        Ok(())
    );
    assert!(pair_for_profile(StealthProfile::Ie11Windows).is_none());
}

#[test]
fn coherence_gate_third_check_is_meaningful_for_firefox() {
    // Prove the browser-family arm actually constrains: FirefoxWindows resolves
    // to the firefox HTTP family, which is exactly what its UA browser implies.
    let (_, h2) = pair_for_profile(StealthProfile::FirefoxWindows).unwrap();
    assert_eq!(h2.family, "firefox");
    assert_eq!(
        transport_family_for_browser(UserAgentBrowser::Firefox),
        Some(h2.family)
    );
    // ...and a Chrome-family persona resolves to "chrome", not "firefox".
    let (_, chrome_h2) = pair_for_profile(StealthProfile::ChromeWindowsStable).unwrap();
    assert_eq!(chrome_h2.family, "chrome");
    assert_ne!(chrome_h2.family, h2.family);
}

#[test]
fn configured_host_initial_ttl_reads_a_sane_value_on_linux() {
    // Non-privileged runtime read; host-independent assertion on the *shape* of
    // the value, never a hardcoded TTL (the host may have retuned its default).
    match configured_host_initial_ttl() {
        // A real configured TTL is a positive byte (Linux default is 64, but a
        // retuned host could read 128/255 (all valid)).
        Some(ttl) => assert!(ttl > 0, "configured TTL must be a positive byte, got {ttl}"),
        // Unreadable (non-Linux, or sysctl absent) must be None, never a guess.
        None => assert!(
            cfg!(not(target_os = "linux"))
                || std::fs::metadata("/proc/sys/net/ipv4/ip_default_ttl").is_err(),
            "Linux with a readable ip_default_ttl must yield Some, not None"
        ),
    }
}

#[test]
fn configured_ttl_composes_with_the_coherence_predicate() {
    use crate::fingerprint::{infer_initial_ttl, os_network_coherence};

    // When the configured TTL is readable, feeding it to the predicate must
    // agree with de-hopping it directly (the documented composition path).
    if let Some(ttl) = configured_host_initial_ttl() {
        let inferred = infer_initial_ttl(ttl);
        // A persona whose stack matches the inferred band is coherent; pick the
        // band's canonical persona from the inferred initial TTL itself.
        let band_persona = match inferred {
            128 => StealthProfile::FirefoxWindows,
            // 64 (Unix) and any other band fall here; FirefoxLinux carries TTL 64.
            _ => StealthProfile::FirefoxLinux,
        };
        let verdict = os_network_coherence(band_persona, ttl);
        if inferred == 64 || inferred == 128 {
            assert!(
                verdict.is_coherent(),
                "configured TTL {ttl} (band {inferred}) must be coherent with its band persona"
            );
        }
    }
}
