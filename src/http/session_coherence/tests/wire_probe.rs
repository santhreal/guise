use super::*;

#[test]
fn wire_self_probe_coherent_when_every_layer_matches() {
    // FirefoxLinux egressing a Linux host: TTL 55 de-hops to 64 (Linux), and the
    // observed Akamai equals the Firefox model. Both layers agree → Coherent.
    let capture = WireCapture {
        observed_ttl: Some(55),
        akamai_fingerprint: Some(FIREFOX_H2.akamai_fingerprint()),
        observed_ja4t: None,
    };
    assert_eq!(
        persona_wire_self_probe(StealthProfile::FirefoxLinux, &capture),
        WireSelfProbe::Coherent
    );
}

#[test]
fn wire_self_probe_flags_ttl_os_mismatch() {
    // A Windows persona (expects initial TTL 128) egressing a Linux host whose
    // packets arrive with a de-hopped 64 (the classic G017 TCP-OS tell).
    let capture = WireCapture {
        observed_ttl: Some(55),
        akamai_fingerprint: None,
        observed_ja4t: None,
    };
    match persona_wire_self_probe(StealthProfile::FirefoxWindows, &capture) {
        WireSelfProbe::Incoherent(mismatches) => {
            assert_eq!(mismatches.len(), 1);
            assert_eq!(
                mismatches[0],
                WireLayerMismatch::Ttl {
                    expected_os: UserAgentPlatform::Windows,
                    expected_initial_ttl: 128,
                    observed_initial_ttl: 64,
                }
            );
        }
        other => panic!("expected Incoherent Ttl, got {other:?}"),
    }
}

#[test]
fn wire_self_probe_flags_akamai_engine_mismatch() {
    // A Firefox persona whose egress shows Chrome's Akamai fingerprint, the
    // "persona says Firefox, the H2 wire says Chrome" engine mismatch.
    let capture = WireCapture {
        observed_ttl: Some(55),
        akamai_fingerprint: Some(CHROME_H2.akamai_fingerprint()),
        observed_ja4t: None,
    };
    match persona_wire_self_probe(StealthProfile::FirefoxLinux, &capture) {
        WireSelfProbe::Incoherent(mismatches) => {
            assert_eq!(mismatches.len(), 1, "TTL matches; only Akamai should fail");
            assert_eq!(
                mismatches[0],
                WireLayerMismatch::Akamai {
                    expected: FIREFOX_H2.akamai_fingerprint(),
                    observed: CHROME_H2.akamai_fingerprint(),
                }
            );
        }
        other => panic!("expected Incoherent Akamai, got {other:?}"),
    }
}

#[test]
fn akamai_mismatch_localizes_to_the_exact_h2_fields() {
    // The self-probe flags WHICH layer leaks; the canonical parser then names the
    // exact frame fields, the same un-decorator the cluster near-miss uses, now
    // on the egress self-probe path. A Firefox persona emitting Chrome's H2 on the
    // wire diverges in pseudo-header order (m,p,a,s vs m,a,s,p) and SETTINGS.
    use crate::fingerprint::akamai_h2::AkamaiH2Divergence;

    let capture = WireCapture {
        observed_ttl: None,
        akamai_fingerprint: Some(CHROME_H2.akamai_fingerprint()),
        observed_ja4t: None,
    };
    let mismatch = match persona_wire_self_probe(StealthProfile::FirefoxLinux, &capture) {
        WireSelfProbe::Incoherent(mut m) => m.remove(0),
        other => panic!("expected Incoherent, got {other:?}"),
    };
    let divergences = mismatch
        .akamai_field_divergences()
        .expect("an Akamai mismatch with two parseable sides must localize");

    // observed (Chrome) vs expected (Firefox): pseudo-header order leaks.
    assert!(divergences
        .iter()
        .any(|d| matches!(d, AkamaiH2Divergence::PseudoHeaderOrder { .. })));
    // INITIAL_WINDOW_SIZE (id 4) diverges 6291456 (Chrome) vs 131072 (Firefox).
    assert!(divergences.iter().any(|d| matches!(
        d,
        AkamaiH2Divergence::Setting {
            id: 4,
            observed: Some(6_291_456),
            target: Some(131_072)
        }
    )));

    // A non-Akamai mismatch has no Akamai localization.
    let ttl_only = WireLayerMismatch::Ttl {
        expected_os: crate::fingerprint::UserAgentPlatform::Windows,
        expected_initial_ttl: 128,
        observed_initial_ttl: 64,
    };
    assert!(ttl_only.akamai_field_divergences().is_none());
}

#[test]
fn wire_self_probe_reports_both_layers_failing() {
    // Windows persona, Linux egress TTL, AND a Safari Akamai on the wire: two
    // independent layers betray the persona; both are surfaced, not just the first.
    let capture = WireCapture {
        observed_ttl: Some(55),
        akamai_fingerprint: Some(SAFARI_H2.akamai_fingerprint()),
        observed_ja4t: None,
    };
    match persona_wire_self_probe(StealthProfile::FirefoxWindows, &capture) {
        WireSelfProbe::Incoherent(mismatches) => {
            assert_eq!(mismatches.len(), 2, "both TTL and Akamai must be reported");
            assert!(mismatches
                .iter()
                .any(|m| matches!(m, WireLayerMismatch::Ttl { .. })));
            assert!(mismatches
                .iter()
                .any(|m| matches!(m, WireLayerMismatch::Akamai { .. })));
        }
        other => panic!("expected two mismatches, got {other:?}"),
    }
}

#[test]
fn wire_self_probe_unmeasured_on_empty_capture() {
    // No layer present → explicitly Unmeasured, never a silent pass.
    let capture = WireCapture::default();
    assert!(capture.is_empty());
    assert_eq!(
        persona_wire_self_probe(StealthProfile::FirefoxLinux, &capture),
        WireSelfProbe::Unmeasured
    );
}

#[test]
fn wire_self_probe_skips_unmeasurable_ttl_zero() {
    // A TTL of 0 is unmeasurable; with no other layer the verdict is Unmeasured,
    // not a false Coherent and not a false Mismatch.
    let capture = WireCapture {
        observed_ttl: Some(0),
        akamai_fingerprint: None,
        observed_ja4t: None,
    };
    assert_eq!(
        persona_wire_self_probe(StealthProfile::FirefoxLinux, &capture),
        WireSelfProbe::Unmeasured
    );
}

#[test]
fn wire_self_probe_skips_akamai_when_persona_has_no_h2_model() {
    // IE11 has no modeled HTTP/2 profile; an observed Akamai cannot be asserted
    // against a model we do not have, so that layer is skipped (not failed). With
    // only an unmodelable layer present, the verdict is Unmeasured.
    let capture = WireCapture {
        observed_ttl: None,
        akamai_fingerprint: Some(CHROME_H2.akamai_fingerprint()),
        observed_ja4t: None,
    };
    assert_eq!(
        persona_wire_self_probe(StealthProfile::Ie11Windows, &capture),
        WireSelfProbe::Unmeasured
    );
}

#[test]
fn wire_self_probe_coherent_when_observed_ja4t_matches() {
    // A Windows persona whose egress SYN computes to FoxIO's Windows-11 JA4T is
    // TCP-coherent (the modern detector-facing fingerprint agrees with the model).
    let capture = WireCapture {
        observed_ttl: None,
        akamai_fingerprint: None,
        observed_ja4t: Some("64240_2-1-3-1-1-4_1460_8".to_string()),
    };
    assert_eq!(
        persona_wire_self_probe(StealthProfile::FirefoxWindows, &capture),
        WireSelfProbe::Coherent
    );
}

#[test]
fn wire_self_probe_flags_ja4t_os_mismatch() {
    // A Windows persona whose egress SYN computes to a Linux-shaped JA4T tail is
    // the TCP-layer "TLS says Windows, TCP says Linux" tell. X049's whole point.
    let capture = WireCapture {
        observed_ttl: None,
        akamai_fingerprint: None,
        observed_ja4t: Some("29200_2-4-8-1-3_1460_7".to_string()),
    };
    match persona_wire_self_probe(StealthProfile::FirefoxWindows, &capture) {
        WireSelfProbe::Incoherent(mismatches) => {
            assert_eq!(mismatches.len(), 1);
            match &mismatches[0] {
                WireLayerMismatch::Ja4t { expected, observed } => {
                    assert_eq!(expected, "64240_2-1-3-1-1-4_1460_8");
                    assert_eq!(observed, "29200_2-4-8-1-3_1460_7");
                }
                other => panic!("expected a Ja4t mismatch, got {other:?}"),
            }
        }
        other => panic!("expected Incoherent, got {other:?}"),
    }
}

#[test]
fn wire_self_probe_ja4t_wildcards_autotuned_window() {
    // A Linux persona's real SYN carries a concrete autotuned window (29200) that
    // differs from the model's `*`; the probe must NOT flag that as a tell as long
    // as the option/MSS/wscale tail agrees.
    let capture = WireCapture {
        observed_ttl: None,
        akamai_fingerprint: None,
        observed_ja4t: Some("29200_2-4-8-1-3_1460_7".to_string()),
    };
    assert_eq!(
        persona_wire_self_probe(StealthProfile::FirefoxLinux, &capture),
        WireSelfProbe::Coherent
    );
}

#[test]
fn wire_self_probe_coherent_on_the_real_captured_tuned_linux_syn() {
    // REAL-WIRE REGRESSION (2026-06-13): the egress SYN captured from this Linux
    // host via tcpdump is JA4T `64240_2-4-8-1-3_1460_10` (wscale 10, large
    // net.ipv4.tcp_rmem, vs the modeled stock Linux wscale 7). A Linux persona on
    // a real Linux host IS coherent: the option layout `2-4-8-1-3` + MSS 1460 (the
    // OS discriminators) agree; the host-variable window-scale is advisory. Before
    // the fix this FALSE-FLAGGED a fully-legitimate persona as Ja4t-incoherent.
    let capture = WireCapture {
        observed_ttl: None,
        akamai_fingerprint: None,
        observed_ja4t: Some("64240_2-4-8-1-3_1460_10".to_string()),
    };
    assert_eq!(
        persona_wire_self_probe(StealthProfile::ChromeLinux, &capture),
        WireSelfProbe::Coherent,
        "the real captured tuned-Linux SYN must be coherent with a Linux persona"
    );
    // The discrimination is intact: the SAME real wire betrays a WINDOWS persona,
    // because the option layout (Linux `2-4-8-1-3`) ≠ Windows `2-1-3-1-1-4`.
    match persona_wire_self_probe(StealthProfile::ChromeWindowsStable, &capture) {
        WireSelfProbe::Incoherent(mismatches) => assert!(
            mismatches
                .iter()
                .any(|m| matches!(m, WireLayerMismatch::Ja4t { .. })),
            "a Windows persona on the real Linux egress must still leak a Ja4t tell"
        ),
        other => {
            panic!("expected Incoherent for a Windows persona on real Linux egress, got {other:?}")
        }
    }
}

#[test]
fn wire_self_probe_stacks_ttl_and_ja4t_mismatches_together() {
    // Both lower layers betray a Windows persona on a Linux host at once: de-hopped
    // TTL 64 (expected 128) AND a Linux-tail JA4T. Each leaks independently, so the
    // self-probe names both rather than stopping at the first.
    let capture = WireCapture {
        observed_ttl: Some(54),
        akamai_fingerprint: None,
        observed_ja4t: Some("29200_2-4-8-1-3_1460_7".to_string()),
    };
    match persona_wire_self_probe(StealthProfile::FirefoxWindows, &capture) {
        WireSelfProbe::Incoherent(mismatches) => {
            assert_eq!(mismatches.len(), 2, "both TTL and JA4T should be flagged");
            assert!(mismatches
                .iter()
                .any(|m| matches!(m, WireLayerMismatch::Ttl { .. })));
            assert!(mismatches
                .iter()
                .any(|m| matches!(m, WireLayerMismatch::Ja4t { .. })));
        }
        other => panic!("expected Incoherent with two layers, got {other:?}"),
    }
}
