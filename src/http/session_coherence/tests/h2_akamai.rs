use super::*;

#[test]
fn h2_profiles_have_distinct_initial_window_increments() {
    assert_ne!(
        CHROME_H2.initial_window_increment,
        FIREFOX_H2.initial_window_increment
    );
    assert_ne!(
        CHROME_H2.initial_window_increment,
        SAFARI_H2.initial_window_increment
    );
    assert_ne!(
        FIREFOX_H2.initial_window_increment,
        SAFARI_H2.initial_window_increment
    );
}

#[test]
fn chrome_and_firefox_h2_disable_push_explicitly_safari_omits_it() {
    // Both Chrome and modern Firefox send SETTINGS_ENABLE_PUSH(2)=0; the live
    // tls.peet.ws Akamai capture (1:65536;2:0;4:131072;5:16384) confirms FF does.
    assert!(CHROME_H2
        .settings
        .iter()
        .any(|&(id, value)| id == 2 && value == 0));
    assert!(FIREFOX_H2
        .settings
        .iter()
        .any(|&(id, value)| id == 2 && value == 0));
    // Safari's H2 SETTINGS are 3/4/8 (it does not carry the push setting).
    assert!(!SAFARI_H2.settings.iter().any(|&(id, _)| id == 2));
}

#[test]
fn firefox_h2_settings_are_in_wire_order() {
    // The Akamai fingerprint is order-sensitive; FF emits 1,2,4,5 ascending.
    let ids: Vec<u16> = FIREFOX_H2.settings.iter().map(|&(id, _)| id).collect();
    assert_eq!(ids, vec![1, 2, 4, 5]);
}

#[test]
fn safari_h2_carries_enable_connect_protocol_setting() {
    assert!(SAFARI_H2.settings.iter().any(|&(id, _)| id == 8));
    assert!(!CHROME_H2.settings.iter().any(|&(id, _)| id == 8));
    assert!(!FIREFOX_H2.settings.iter().any(|&(id, _)| id == 8));
}

#[test]
fn akamai_fingerprint_renders_all_four_segments_faithfully() {
    // The full Akamai string is SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-order.
    // Firefox is wire-verified against reynard FF-150 in tls_fingerprint.
    assert_eq!(
        FIREFOX_H2.akamai_fingerprint(),
        "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"
    );
    assert_eq!(
        CHROME_H2.akamai_fingerprint(),
        "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    );
    assert_eq!(
        SAFARI_H2.akamai_fingerprint(),
        "3:100;4:2097152;8:1|10485760|0|m,s,p,a"
    );
}

#[test]
fn akamai_fingerprint_always_has_four_pipe_segments() {
    // Format contract: a parser splitting on `|` must always see exactly 4 parts.
    for h2 in [CHROME_H2, FIREFOX_H2, SAFARI_H2] {
        let rendered = h2.akamai_fingerprint();
        let segments = rendered.split('|').count();
        assert_eq!(segments, 4, "{}: not 4-part akamai ({rendered})", h2.family);
    }
}

#[test]
fn structured_h2_model_matches_the_catalogue_for_wire_measured_families() {
    // Dedup + coherence (Vectors 7/10). The structured `H2Profile` model here and
    // the flat `fingerprint::tls_targets` catalogue independently encode each
    // family's Akamai H2 fingerprint, two sources that can drift. For the two
    // families with a live wire measurement on this fleet they MUST render the SAME
    // string, or a WAF-capture comparison uses a different reference depending on
    // which source the caller reached. Chrome's current shape is the measured
    // chrome-146; Firefox's is the measured firefox-150 (== firefox-151, identical
    // H2). Safari is handled separately below, it has no Apple-hardware measurement
    // here and its two sources currently diverge.
    use crate::fingerprint::tls_targets::lookup;
    assert_eq!(
        CHROME_H2.akamai_fingerprint(),
        lookup("chrome-146-linux").unwrap().akamai_h2,
        "CHROME_H2 model must render the measured chrome-146 catalogue Akamai string"
    );
    let ff = FIREFOX_H2.akamai_fingerprint();
    assert_eq!(
        ff,
        lookup("firefox-150-linux").unwrap().akamai_h2,
        "FIREFOX_H2 model must render the measured firefox-150 catalogue Akamai string"
    );
    assert_eq!(
        ff,
        lookup("firefox-151-linux").unwrap().akamai_h2,
        "FF-150 and FF-151 share one H2 string, so the model must match both"
    );
}

#[test]
fn every_h2_profile_render_is_accepted_by_the_canonical_akamai_parser() {
    // Dedup/coherence guard (Vector 7/10): the EMIT model (`H2Profile`, which
    // renders the wire string) and the canonical PARSE model
    // (`fingerprint::akamai_h2::AkamaiH2Fingerprint`) are two views of one format.
    // Every persona the emit model renders MUST parse back through the canonical
    // model, round-trip byte-for-byte, and decode to the SAME structured fields
    // the profile declares. If either model drifts, this fails instead of letting
    // the self-probe compare against a string the parser would reject.
    use crate::fingerprint::akamai_h2::AkamaiH2Fingerprint;

    for h2 in [CHROME_H2, FIREFOX_H2, SAFARI_H2] {
        let rendered = h2.akamai_fingerprint();
        let parsed = AkamaiH2Fingerprint::parse(&rendered).unwrap_or_else(|e| {
            panic!(
                "{}: canonical parser rejected its own render `{rendered}`: {e}",
                h2.family
            )
        });
        assert_eq!(
            parsed.to_canonical(),
            rendered,
            "{}: round-trip drift",
            h2.family
        );

        // SETTINGS decode to exactly the declared (id, value) pairs, in order.
        let parsed_settings: Vec<(u16, u32)> =
            parsed.settings.iter().map(|s| (s.id, s.value)).collect();
        assert_eq!(
            parsed_settings,
            h2.settings.to_vec(),
            "{}: settings",
            h2.family
        );

        // window_update + pseudo-header order agree.
        assert_eq!(
            parsed.window_update, h2.initial_window_increment,
            "{}: wu",
            h2.family
        );
        let pseudo = parsed
            .pseudo_header_order
            .iter()
            .map(|p| p.code().to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            pseudo, h2.pseudo_header_order,
            "{}: pseudo order",
            h2.family
        );
    }
}

#[test]
fn pseudo_header_order_is_a_distinct_per_engine_discriminator() {
    // The four orders must differ across engines, that is the whole point of the
    // segment. m=:method a=:authority s=:scheme p=:path.
    assert_eq!(CHROME_H2.pseudo_header_order, "m,a,s,p");
    assert_eq!(FIREFOX_H2.pseudo_header_order, "m,p,a,s");
    assert_eq!(SAFARI_H2.pseudo_header_order, "m,s,p,a");
    assert_ne!(
        CHROME_H2.pseudo_header_order,
        FIREFOX_H2.pseudo_header_order
    );
    assert_ne!(CHROME_H2.pseudo_header_order, SAFARI_H2.pseudo_header_order);
    assert_ne!(
        FIREFOX_H2.pseudo_header_order,
        SAFARI_H2.pseudo_header_order
    );
    // Every order is a permutation of exactly the four HTTP/2 pseudo-headers.
    for h2 in [CHROME_H2, FIREFOX_H2, SAFARI_H2] {
        let mut letters: Vec<&str> = h2.pseudo_header_order.split(',').collect();
        letters.sort_unstable();
        assert_eq!(letters, vec!["a", "m", "p", "s"], "{}", h2.family);
    }
}

#[test]
fn modern_engines_send_no_standalone_priority_frame() {
    // Chrome/Firefox-150/Safari prioritize via SETTINGS/RFC 9218, not PRIORITY
    // frames on open → the Akamai PRIORITY segment is "0".
    assert_eq!(CHROME_H2.priority, "0");
    assert_eq!(FIREFOX_H2.priority, "0");
    assert_eq!(SAFARI_H2.priority, "0");
}

#[test]
fn structured_chrome_h2_matches_the_flat_chrome_catalogue() {
    // Dedup/coherence guard (Vector 7/10): the structured CHROME_H2 model and the
    // current flat chrome_tls snapshot are two encodings of the SAME canonical
    // Chrome wire fingerprint, so their rendered Akamai strings must be identical.
    // If a future edit drifts one, this fails instead of silently shipping two
    // disagreeing Chrome fingerprints.
    let flat = crate::fingerprint::chrome_tls::expected_fingerprint(134, "Linux")
        .expect("Chrome 134/Linux snapshot must ship");
    assert_eq!(
        CHROME_H2.akamai_fingerprint(),
        flat.h2_fingerprint,
        "structured CHROME_H2 drifted from the flat chrome_tls catalogue"
    );
}

#[test]
fn pseudo_header_orders_agree_with_the_versioned_target_catalogue() {
    // The pseudo-header order is an engine constant across versions, so the
    // structured model's order must equal the order segment of the matching
    // tls_targets entry (even when SETTINGS differ by version). Safari has no
    // measured flat target in the built-in catalogue, so only the measured
    // Chrome/Firefox entries are cross-checked here.
    let order_of = |label: &str| -> String {
        let t = crate::fingerprint::tls_targets::lookup(label)
            .unwrap_or_else(|| panic!("{label} target must ship"));
        t.akamai_h2
            .split('|')
            .nth(3)
            .expect("akamai has 4 segments")
            .to_string()
    };
    assert_eq!(CHROME_H2.pseudo_header_order, order_of("chrome-146-linux"));
    assert_eq!(
        FIREFOX_H2.pseudo_header_order,
        order_of("firefox-150-linux")
    );
    assert_eq!(
        FIREFOX_H2.pseudo_header_order,
        order_of("firefox-151-linux"),
        "FF-150 and FF-151 share the same H2 pseudo-header order"
    );
}
