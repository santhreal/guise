//! Tests for wire-fingerprint cluster membership (G048–G051).

use super::*;
// `FingerprintTarget` and `FINGERPRINT_TARGETS` are already in scope via
// `super::*` (cluster.rs imports them privately; child modules see them). Only
// `lookup` needs an explicit import here.
use crate::fingerprint::tls_targets::lookup;

/// Build a full 4-surface observation from a catalogue target.
fn observe_full(target: &FingerprintTarget) -> ObservedFingerprint {
    ObservedFingerprint {
        ja3: Some(target.ja3.to_string()),
        ja4: Some(target.ja4.to_string()),
        akamai_h2: Some(target.akamai_h2.to_string()),
        peet_h2: Some(target.peet_h2.to_string()),
    }
}

/// Build a target that is byte-identical to `chrome-146-linux` but carries a
/// different label (the canonical "same cluster, two OS labels" case).
fn chrome146_clone(label: &'static str) -> FingerprintTarget {
    let base = lookup("chrome-146-linux").expect("chrome-146-linux must ship");
    FingerprintTarget {
        label,
        ja3: base.ja3,
        ja4: base.ja4,
        akamai_h2: base.akamai_h2,
        peet_h2: base.peet_h2,
    }
}

/// Build a Chrome-146-shaped target whose JA3 differs only in group order, so
/// its JA4/Akamai still collide but a probed JA3 will contradict it.
fn chrome146_pq_variant(label: &'static str) -> FingerprintTarget {
    let base = lookup("chrome-146-linux").expect("chrome-146-linux must ship");
    // Chrome-146's groups are `4588-29-23-24`; reorder them so the JA3 string
    // differs while cipher/extension counts (and therefore the JA4) stay the same.
    let reordered_groups = "29-23-24-4588";
    let ja3 = format!(
        "771,{},{},{},0",
        base.ja3.split(',').nth(1).unwrap(),
        base.ja3.split(',').nth(2).unwrap(),
        reordered_groups
    );
    FingerprintTarget {
        label,
        ja3: Box::leak(ja3.into_boxed_str()),
        ja4: base.ja4,
        akamai_h2: base.akamai_h2,
        peet_h2: base.peet_h2,
    }
}

// ── SurfaceMatch tri-state ────────────────────────────────────────────────

#[test]
fn surface_match_distinguishes_not_probed_from_mismatch() {
    assert_eq!(SurfaceMatch::of(Some("x"), "x"), SurfaceMatch::Matched);
    assert_eq!(SurfaceMatch::of(Some("x"), "y"), SurfaceMatch::Mismatched);
    assert_eq!(SurfaceMatch::of(None, "y"), SurfaceMatch::NotProbed);

    assert!(SurfaceMatch::Matched.is_matched());
    assert!(!SurfaceMatch::Matched.is_mismatched());
    assert!(SurfaceMatch::Mismatched.is_mismatched());
    assert!(!SurfaceMatch::Mismatched.is_matched());
    // NotProbed is neither (the load-bearing distinction).
    assert!(!SurfaceMatch::NotProbed.is_matched());
    assert!(!SurfaceMatch::NotProbed.is_mismatched());
}

// ── Positive: in-cluster ──────────────────────────────────────────────────

#[test]
fn firefox_150_ja4_plus_akamai_is_in_cluster() {
    let ff = lookup("firefox-150-linux").expect("ff-150 target must ship");
    let observed = ObservedFingerprint {
        ja4: Some(ff.ja4.to_string()),
        akamai_h2: Some(ff.akamai_h2.to_string()),
        ..Default::default()
    };
    let verdict = classify_observed(&observed);
    assert!(verdict.is_in_cluster(), "got {verdict:?}");
    assert!(verdict.cluster_labels().contains(&"firefox-150-linux"));
}

#[test]
fn firefox_150_ja4_alone_is_sufficient_for_membership() {
    // JA4 is the primary axis: a JA4 match with nothing else probed is in-cluster
    // (Akamai NotProbed is not a contradiction).
    let ff = lookup("firefox-150-linux").unwrap();
    let observed = ObservedFingerprint::from_ja4(ff.ja4.to_string());
    let verdict = classify_observed(&observed);
    assert!(verdict.is_in_cluster(), "got {verdict:?}");
    assert!(verdict.cluster_labels().contains(&"firefox-150-linux"));
}

#[test]
fn firefox_150_full_observation_matches_only_firefox_150() {
    // FF-150 and FF-151 share the JA4 extension-hash (`e6dcd7ae0a9e`) but differ
    // on the JA4 cipher-hash AND the full JA4 string, so a full FF-150
    // observation must NOT collapse into the FF-151 cluster.
    let ff150 = lookup("firefox-150-linux").unwrap();
    let verdict = classify_observed(&observe_full(ff150));
    let labels = verdict.cluster_labels();
    assert!(labels.contains(&"firefox-150-linux"), "got {labels:?}");
    assert!(
        !labels.contains(&"firefox-151-linux"),
        "FF-150 must not be a member of the FF-151 cluster: {labels:?}"
    );
}

#[test]
fn firefox_150_and_151_are_distinct_clusters() {
    // Two measured Firefox versions have different JA4s; each fully-observed
    // target must match only its own label.
    let ff150 = lookup("firefox-150-linux").unwrap();
    let ff151 = lookup("firefox-151-linux").unwrap();
    assert_ne!(ff150.ja4, ff151.ja4);

    let labels150 = classify_observed(&observe_full(ff150)).cluster_labels();
    assert!(labels150.contains(&"firefox-150-linux"));
    assert!(!labels150.contains(&"firefox-151-linux"));

    let labels151 = classify_observed(&observe_full(ff151)).cluster_labels();
    assert!(labels151.contains(&"firefox-151-linux"));
    assert!(!labels151.contains(&"firefox-150-linux"));
}

#[test]
fn chrome_146_linux_and_synthetic_mac_are_one_cluster() {
    // A synthetic OS variant with identical fingerprints collides in the same
    // cluster (the anti-uniqueness property the catalogue is built for).
    let chrome = lookup("chrome-146-linux").unwrap();
    let synthetic_mac = chrome146_clone("chrome-146-mac");
    let catalogue = [chrome146_clone("chrome-146-linux-clone"), synthetic_mac];
    let observed = ObservedFingerprint {
        ja4: Some(chrome.ja4.to_string()),
        akamai_h2: Some(chrome.akamai_h2.to_string()),
        ..Default::default()
    };
    let labels = classify_against(&observed, &catalogue).cluster_labels();
    assert!(labels.contains(&"chrome-146-linux-clone"), "got {labels:?}");
    assert!(labels.contains(&"chrome-146-mac"), "got {labels:?}");
    // A Chrome shape must never land in a Firefox cluster.
    assert!(!labels.contains(&"firefox-150-linux"), "got {labels:?}");
    assert!(!labels.contains(&"firefox-151-linux"), "got {labels:?}");
}

#[test]
fn probing_ja3_narrows_the_chrome_cluster() {
    // Same Chrome JA4+Akamai, but now we also probe JA3 = chrome-146-linux's JA3.
    // A synthetic PQ variant's JA3 differs only in group order, so it now
    // CONTRADICTS (it drops out, leaving the two non-PQ labels).
    let chrome = lookup("chrome-146-linux").unwrap();
    let catalogue = [
        chrome146_clone("chrome-146-linux-clone"),
        chrome146_clone("chrome-146-mac"),
        chrome146_pq_variant("chrome-146-linux-pq"),
    ];
    let observed = ObservedFingerprint {
        ja3: Some(chrome.ja3.to_string()),
        ja4: Some(chrome.ja4.to_string()),
        akamai_h2: Some(chrome.akamai_h2.to_string()),
        ..Default::default()
    };
    let labels = classify_against(&observed, &catalogue).cluster_labels();
    assert!(labels.contains(&"chrome-146-linux-clone"), "got {labels:?}");
    assert!(labels.contains(&"chrome-146-mac"), "got {labels:?}");
    assert!(
        !labels.contains(&"chrome-146-linux-pq"),
        "a probed, contradicting JA3 must drop the PQ variant: {labels:?}"
    );
}

// ── Negative / adversarial: distinguishable ───────────────────────────────

#[test]
fn alien_ja4_is_distinguishable_with_no_nearest() {
    let alien = ObservedFingerprint::from_ja4("t13d9999h2_deadbeefcafe_0123456789ab");
    match classify_observed(&alien) {
        ClusterVerdict::Distinguishable {
            nearest,
            weak_evidence_only,
        } => {
            assert!(nearest.is_none(), "no surface should have matched");
            assert!(
                !weak_evidence_only,
                "JA4 *was* probed, so evidence is strong"
            );
        }
        other => panic!("expected Distinguishable, got {other:?}"),
    }
}

#[test]
fn ja4_firefox_but_akamai_chrome_is_incoherent_not_member() {
    // The cross-layer tell: TLS says Firefox-150, the H2 frame says Chrome. A
    // probed, contradicting Akamai must BREAK membership (not be ignored).
    let ff = lookup("firefox-150-linux").unwrap();
    let chrome = lookup("chrome-146-linux").unwrap();
    let observed = ObservedFingerprint {
        ja4: Some(ff.ja4.to_string()),
        akamai_h2: Some(chrome.akamai_h2.to_string()),
        ..Default::default()
    };
    match classify_observed(&observed) {
        ClusterVerdict::Distinguishable { nearest, .. } => {
            let nearest = nearest.expect("FF-150 JA4 matched, so a nearest exists");
            assert_eq!(nearest.label, "firefox-150-linux");
            assert!(nearest.ja4.is_matched());
            assert!(nearest.akamai.is_mismatched());
            assert!(nearest.contradicts());
            assert!(!nearest.is_member());
        }
        other => panic!("expected Distinguishable, got {other:?}"),
    }
}

#[test]
fn ja3_only_observation_is_weak_evidence() {
    // Recovering only a JA3 string (no JA4) can never assert membership. JA4 is
    // the required axis (but the nearest still reflects the JA3 match).
    let ff = lookup("firefox-150-linux").unwrap();
    let observed = ObservedFingerprint {
        ja3: Some(ff.ja3.to_string()),
        ..Default::default()
    };
    match classify_observed(&observed) {
        ClusterVerdict::Distinguishable {
            nearest,
            weak_evidence_only,
        } => {
            assert!(weak_evidence_only, "JA4 was not probed");
            let nearest = nearest.expect("JA3 matched FF-150");
            assert_eq!(nearest.label, "firefox-150-linux");
            assert!(nearest.ja3.is_matched());
            assert_eq!(nearest.ja4, SurfaceMatch::NotProbed);
        }
        other => panic!("expected Distinguishable, got {other:?}"),
    }
}

#[test]
fn akamai_only_observation_is_not_membership() {
    // Akamai alone is the corroborator, not the primary axis: it cannot carry
    // membership even when it matches.
    let ff = lookup("firefox-150-linux").unwrap();
    let observed = ObservedFingerprint {
        akamai_h2: Some(ff.akamai_h2.to_string()),
        ..Default::default()
    };
    let verdict = classify_observed(&observed);
    assert!(
        !verdict.is_in_cluster(),
        "akamai-only must not be in-cluster"
    );
    match verdict {
        ClusterVerdict::Distinguishable {
            weak_evidence_only, ..
        } => assert!(weak_evidence_only),
        other => panic!("expected Distinguishable, got {other:?}"),
    }
}

#[test]
fn incoherent_akamai_near_miss_localizes_to_a_named_h2_field() {
    // Compose the cluster verdict with the structured Akamai model: when FF-150's
    // JA4 matches but the probed H2 frame is Chrome's, the cluster reports a
    // contradicting Akamai surface (Mismatched), and `akamai_h2` then names the
    // exact frame field (pseudo-header order m,p,a,s vs m,a,s,p) the operator
    // must fix. This is the L2 un-decorator: not "H2 differs" but "H2 differs HERE".
    use crate::fingerprint::akamai_h2::{AkamaiH2Divergence, AkamaiH2Fingerprint, PseudoHeader};

    let ff = lookup("firefox-150-linux").unwrap();
    let chrome = lookup("chrome-146-linux").unwrap();
    let observed = ObservedFingerprint {
        ja4: Some(ff.ja4.to_string()),
        akamai_h2: Some(chrome.akamai_h2.to_string()),
        ..Default::default()
    };
    let nearest = match classify_observed(&observed) {
        ClusterVerdict::Distinguishable { nearest, .. } => nearest.expect("FF-150 JA4 matched"),
        other => panic!("expected Distinguishable, got {other:?}"),
    };
    assert_eq!(nearest.label, "firefox-150-linux");
    assert!(nearest.akamai.is_mismatched());

    // The cluster flagged WHICH surface; akamai_h2 explains WHY, field by field.
    let observed_h2 = AkamaiH2Fingerprint::parse(chrome.akamai_h2).unwrap();
    let target_h2 = AkamaiH2Fingerprint::parse(ff.akamai_h2).unwrap();
    let divergences = observed_h2.diff(&target_h2);
    assert!(divergences.iter().any(|d| matches!(
        d,
        AkamaiH2Divergence::PseudoHeaderOrder { observed, target }
            if observed.first() == Some(&PseudoHeader::Method)
            && observed.get(1) == Some(&PseudoHeader::Authority)
            && target.get(1) == Some(&PseudoHeader::Path)
    )));
}

// ── ClusterMatch helpers ──────────────────────────────────────────────────

#[test]
fn matched_surfaces_and_contradicts_count_correctly() {
    let m = ClusterMatch {
        label: "x",
        ja3: SurfaceMatch::Matched,
        ja4: SurfaceMatch::Matched,
        akamai: SurfaceMatch::NotProbed,
        peet: SurfaceMatch::Mismatched,
    };
    assert_eq!(m.matched_surfaces(), 2);
    assert!(m.contradicts(), "a probed peet mismatch contradicts");
    assert!(
        !m.is_member(),
        "contradiction breaks membership despite JA4 match"
    );
    assert!(m.any_match());

    let clean = ClusterMatch {
        label: "y",
        ja3: SurfaceMatch::NotProbed,
        ja4: SurfaceMatch::Matched,
        akamai: SurfaceMatch::NotProbed,
        peet: SurfaceMatch::NotProbed,
    };
    assert_eq!(clean.matched_surfaces(), 1);
    assert!(!clean.contradicts());
    assert!(clean.is_member());
}

// ── classify_against edge cases ───────────────────────────────────────────

#[test]
fn empty_catalogue_is_distinguishable() {
    static NONE: &[FingerprintTarget] = &[];
    let observed = ObservedFingerprint::from_ja4("t13d1717h2_5b57614c22b0_e6dcd7ae0a9e");
    match classify_against(&observed, NONE) {
        ClusterVerdict::Distinguishable {
            nearest,
            weak_evidence_only,
        } => {
            assert!(nearest.is_none());
            assert!(!weak_evidence_only, "JA4 was probed even with no targets");
        }
        other => panic!("expected Distinguishable, got {other:?}"),
    }
}

// ── Catalogue self-consistency (property over every bundled target) ───────

#[test]
fn every_bundled_target_is_a_member_when_fully_observed() {
    for target in FINGERPRINT_TARGETS {
        let verdict = classify_observed(&observe_full(target));
        assert!(
            verdict.is_in_cluster(),
            "{}: fully-observed target must be in its own cluster, got {verdict:?}",
            target.label
        );
        assert!(
            verdict.cluster_labels().contains(&target.label),
            "{}: own label missing from {:?}",
            target.label,
            verdict.cluster_labels()
        );
    }
}

#[test]
fn firefox_150_catalogue_values_are_the_measured_shape() {
    // Lock the measured 2026-06-12 post-cipher-fix FF-150 values so a catalogue
    // edit that regresses them fails here, not silently in the field.
    let ff = lookup("firefox-150-linux").expect("ff-150 must ship");
    assert_eq!(ff.ja4, "t13d1717h2_5b57614c22b0_e6dcd7ae0a9e");
    assert_eq!(
        ff.akamai_h2,
        "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"
    );
    // peet.ws reports `akamai_fingerprint_hash` as md5(akamai_fingerprint); this
    // is that md5 of the akamai_h2 above (NOT a hand-typed literal, the prior
    // value `8cc4ac50…` was fabricated and could never match a real FF-150).
    assert_eq!(ff.peet_h2, "6ea73faa8fc5aac76bded7bd238f6433");
    assert_eq!(
        ff.peet_h2,
        crate::fingerprint::ja3::md5_string(ff.akamai_h2),
        "peet_h2 must be the real md5 of akamai_h2"
    );
    // 17-cipher shape (post-fix): JA4 cipher-count digits and the presence of
    // 0xc009 (49161) in the JA3 cipher list both confirm the restored cipher.
    assert!(
        ff.ja4.starts_with("t13d1717h2_"),
        "must be the 17-cipher shape"
    );
    assert!(
        ff.ja3.contains("-49161-"),
        "0xc009 (ecdhe_ecdsa_aes_128_sha) must be present: {}",
        ff.ja3
    );
}
