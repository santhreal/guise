use super::*;
use crate::fingerprint::tls_profiles::{compute_ja4_string, profile_for_stealth_profile};
use crate::fingerprint::tls_targets::FINGERPRINT_TARGETS;
use crate::fingerprint::{
    infer_initial_ttl, profile_platform, profile_user_agent, user_agent_facts, StealthProfile,
    ROTATION_PROFILES,
};
use std::collections::HashSet;

/// The populated real-browser JA4 cluster used by the anti-uniqueness guard
/// (G048/G049). A persona whose TLS ClientHello falls outside this set is
/// trackable even if every field is internally valid.
fn populated_ja4_cluster() -> HashSet<&'static str> {
    let mut set: HashSet<&str> = FINGERPRINT_TARGETS.iter().map(|t| t.ja4).collect();
    // Measured Safari 18 / coretls TLS ClientHello. Safari is not a built-in
    // target because no Apple-hardware H2 capture exists on this fleet, but its
    // TLS fingerprint was captured and belongs to the populated cluster.
    set.insert("t13d2014h2_a09f3c656075_2a6581477f52");
    set
}

#[test]
fn every_rotation_persona_full_network_fingerprint_is_populated_and_self_coherent() {
    // G051: the full network fingerprint (JA3+JA4 + H2 + TCP) for every persona
    // in the rotation must land in a populated real-browser cluster AND every
    // layer must describe the same (browser, OS) identity. This is the positive
    // regression guard that a future persona cannot silently ship a distinctive
    // or cross-layer-incoherent network fingerprint.
    let populated = populated_ja4_cluster();

    for &profile in ROTATION_PROFILES {
        // TLS layer: a real, populated ClientHello shape.
        let tls = profile_for_stealth_profile(profile)
            .unwrap_or_else(|| panic!("{profile:?} must have a TLS catalogue entry"));
        let ja4 = compute_ja4_string(tls);
        assert!(
            populated.contains(ja4.as_str()),
            "{profile:?} ({}) emits JA4 {ja4} which is not in the populated real-browser cluster",
            tls.name
        );

        // TCP/IP + HTTP/2 + header-order layers: one coherent transport identity.
        let transport = transport_coherence_for_profile(profile)
            .unwrap_or_else(|| panic!("{profile:?} must have a modeled transport profile"));
        assert_eq!(
            transport.network.os,
            profile_platform(profile),
            "{profile:?}: TCP/IP OS disagrees with the persona's claimed platform"
        );
        assert_eq!(
            infer_initial_ttl(transport.network.initial_ttl),
            transport.network.initial_ttl,
            "{profile:?}: modeled initial TTL must survive a zero-hop de-hop round-trip"
        );
        let ja4t = transport
            .ja4t()
            .unwrap_or_else(|e| panic!("{profile:?}: modeled JA4T must render: {e}"));
        assert!(
            !ja4t.is_empty(),
            "{profile:?}: JA4T must be a non-empty fingerprint string"
        );

        // The browser family implied by the User-Agent must agree with the HTTP/2
        // and header-order families (already asserted by persona_transport_coherence,
        // but the combined guard is the contract G051 is testing).
        let ua_browser = user_agent_facts(profile_user_agent(profile)).browser;
        let expected_family = transport_family_for_browser(ua_browser).unwrap_or_else(|| {
            panic!("{profile:?}: UA browser {ua_browser:?} has no transport family")
        });
        assert_eq!(
            transport.h2.family, expected_family,
            "{profile:?}: HTTP/2 family disagrees with UA browser family"
        );
        assert_eq!(
            transport.header_order.family, expected_family,
            "{profile:?}: header-order family disagrees with UA browser family"
        );
        persona_transport_coherence(profile)
            .unwrap_or_else(|e| panic!("{profile:?}: transport coherence failed: {e:?}"));

        // End-to-end wire self-probe: when every measured layer matches the model,
        // the verdict is Coherent (not just not-Incoherent). This exercises the
        // X049 gate with a complete synthetic capture built from the persona's own
        // expected values.
        let capture = WireCapture {
            observed_ttl: Some(transport.network.initial_ttl),
            akamai_fingerprint: Some(transport.h2.akamai_fingerprint()),
            observed_ja4t: Some(ja4t),
        };
        assert_eq!(
            persona_wire_self_probe(profile, &capture),
            WireSelfProbe::Coherent,
            "{profile:?}: a capture matching the model must be Coherent"
        );
    }
}

#[test]
fn full_network_fingerprint_rejects_a_total_cross_layer_mismatch() {
    // Negative twin for G051: a Windows persona whose TLS *would* be Firefox,
    // but whose egress shows a Linux TTL, Chrome's H2 fingerprint, and a Linux
    // JA4T tail. Every measurable layer contradicts the persona; the self-probe
    // must surface all three mismatches rather than stop at the first.
    let profile = StealthProfile::FirefoxWindows;
    let _transport =
        transport_coherence_for_profile(profile).expect("FirefoxWindows has transport");
    let linux_profile = StealthProfile::FirefoxLinux;
    let linux_transport =
        transport_coherence_for_profile(linux_profile).expect("FirefoxLinux has transport");
    let linux_ja4t = linux_transport
        .ja4t()
        .expect("Linux JA4T renders")
        .to_string();

    let capture = WireCapture {
        // 55 de-hops to 64 (Linux), not the Windows-expected 128.
        observed_ttl: Some(55),
        // Chrome H2 on a Firefox persona.
        akamai_fingerprint: Some(CHROME_H2.akamai_fingerprint()),
        // Linux TCP tail on a Windows persona.
        observed_ja4t: Some(linux_ja4t),
    };

    match persona_wire_self_probe(profile, &capture) {
        WireSelfProbe::Incoherent(mismatches) => {
            assert_eq!(
                mismatches.len(),
                3,
                "all three layers (TTL, Akamai, JA4T) must be flagged"
            );
            assert!(
                mismatches
                    .iter()
                    .any(|m| matches!(m, WireLayerMismatch::Ttl { .. })),
                "TTL mismatch must be surfaced"
            );
            assert!(
                mismatches
                    .iter()
                    .any(|m| matches!(m, WireLayerMismatch::Akamai { .. })),
                "Akamai mismatch must be surfaced"
            );
            assert!(
                mismatches
                    .iter()
                    .any(|m| matches!(m, WireLayerMismatch::Ja4t { .. })),
                "JA4T mismatch must be surfaced"
            );
        }
        other => panic!("expected Incoherent with three mismatches, got {other:?}"),
    }

    // Sanity: the same capture is Coherent for a Linux Firefox persona (the TTL
    // de-hops to Linux, the H2 still mismatches because it is Chrome, so this
    // must NOT be Coherent (it checks the H2 family specifically)).
    let linux_capture = WireCapture {
        observed_ttl: Some(55),
        akamai_fingerprint: Some(CHROME_H2.akamai_fingerprint()),
        observed_ja4t: Some(
            linux_transport
                .ja4t()
                .expect("Linux JA4T renders")
                .to_string(),
        ),
    };
    match persona_wire_self_probe(linux_profile, &linux_capture) {
        WireSelfProbe::Incoherent(mismatches) => {
            assert_eq!(mismatches.len(), 1);
            assert!(
                mismatches
                    .iter()
                    .any(|m| matches!(m, WireLayerMismatch::Akamai { .. })),
                "only the H2 family should mismatch for a Linux persona with Linux TTL+JA4T"
            );
        }
        other => panic!("expected Incoherent Akamai only, got {other:?}"),
    }
}
