use super::*;
use crate::fingerprint::tls_targets::{lookup, FINGERPRINT_TARGETS};

/// Every shipped catalogue target's Akamai H2 string must parse and round-trip
/// byte-for-byte. A target whose `akamai_h2` does not round-trip is malformed
/// data (the parser is the un-decorated replacement for the old
/// `split('|').count() == 4` sniff) (this is the catalogue-integrity tripwire).
#[test]
fn every_catalogue_target_akamai_h2_parses_and_round_trips() {
    for t in FINGERPRINT_TARGETS {
        let fp = AkamaiH2Fingerprint::parse(t.akamai_h2).unwrap_or_else(|e| {
            panic!(
                "{}: akamai_h2 `{}` did not parse: {e}",
                t.label, t.akamai_h2
            )
        });
        let canonical = fp.to_canonical();
        assert_eq!(
            canonical, t.akamai_h2,
            "{}: round-trip changed the string: `{}` -> `{}`",
            t.label, t.akamai_h2, canonical
        );
    }
}

#[test]
fn firefox_150_settings_decode_to_the_measured_values() {
    let ff = lookup("firefox-150-linux").unwrap();
    let fp = AkamaiH2Fingerprint::parse(ff.akamai_h2).unwrap();

    assert_eq!(fp.header_table_size(), Some(65536));
    assert_eq!(fp.enable_push(), Some(0));
    assert_eq!(fp.initial_window_size(), Some(131072));
    assert_eq!(fp.max_frame_size(), Some(16384));
    // Firefox does not advertise these two.
    assert_eq!(fp.max_concurrent_streams(), None);
    assert_eq!(fp.max_header_list_size(), None);

    assert_eq!(fp.window_update, 12_517_377);
    assert!(fp.priorities.is_empty(), "FF-150 sends no PRIORITY frames");
    assert_eq!(
        fp.pseudo_header_order,
        vec![
            PseudoHeader::Method,
            PseudoHeader::Path,
            PseudoHeader::Authority,
            PseudoHeader::Scheme
        ]
    );
}

#[test]
fn settings_order_is_preserved_safari_sends_2_4_3() {
    // Safari's SETTINGS order is `2;4;3`: NOT ascending. The parser must keep
    // the sent order so the canonical form (and any order tell) survives.
    // Kept as an inline fixture because the approximate `safari-17-mac` target
    // was removed from the built-in catalogue.
    let safari = "2:0;4:4194304;3:100|10485760|0|m,s,p,a";
    let fp = AkamaiH2Fingerprint::parse(safari).unwrap();
    let ids: Vec<u16> = fp.settings.iter().map(|s| s.id).collect();
    assert_eq!(ids, vec![2, 4, 3]);
    assert_eq!(fp.to_canonical(), safari);
}

#[test]
fn legacy_firefox_priority_frame_firefox_150_does_not() {
    // Older Firefox (e.g. FF-131) sent a standalone PRIORITY frame on stream 3;
    // FF-150 does not. Kept as an inline fixture because the approximate
    // `firefox-131-linux` target was removed from the built-in catalogue.
    let legacy_ff = "1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s";
    let ff_legacy = AkamaiH2Fingerprint::parse(legacy_ff).unwrap();
    let ff150 = AkamaiH2Fingerprint::parse(lookup("firefox-150-linux").unwrap().akamai_h2).unwrap();

    assert_eq!(
        ff_legacy.priorities,
        vec![H2Priority {
            stream_id: 3,
            exclusive: 0,
            dependent: 0,
            weight: 201
        }]
    );
    assert!(ff150.priorities.is_empty());

    // The version drift is localized to a PRIORITY divergence (plus the
    // ENABLE_PUSH=0 that FF-150 added).
    let divs = ff150.diff(&ff_legacy);
    assert!(divs
        .iter()
        .any(|d| matches!(d, AkamaiH2Divergence::Priority { .. })));
    assert!(divs.iter().any(|d| matches!(
        d,
        AkamaiH2Divergence::Setting {
            id: 2,
            observed: Some(0),
            target: None
        }
    )));
}

#[test]
fn diff_localizes_firefox_vs_chrome_to_pseudo_order_and_settings() {
    let ff = AkamaiH2Fingerprint::parse(lookup("firefox-150-linux").unwrap().akamai_h2).unwrap();
    let chrome = AkamaiH2Fingerprint::parse(lookup("chrome-146-linux").unwrap().akamai_h2).unwrap();

    let divs = ff.diff(&chrome);
    assert!(!divs.is_empty());

    // The cheap, strong discriminator: pseudo-header order m,p,a,s vs m,a,s,p.
    assert!(divs.iter().any(|d| matches!(
        d,
        AkamaiH2Divergence::PseudoHeaderOrder { observed, target }
            if observed == &vec![PseudoHeader::Method, PseudoHeader::Path, PseudoHeader::Authority, PseudoHeader::Scheme]
            && target == &vec![PseudoHeader::Method, PseudoHeader::Authority, PseudoHeader::Scheme, PseudoHeader::Path]
    )));
    // INITIAL_WINDOW_SIZE diverges 131072 vs 6291456.
    assert!(divs.iter().any(|d| matches!(
        d,
        AkamaiH2Divergence::Setting {
            id: 4,
            observed: Some(131072),
            target: Some(6291456)
        }
    )));
    // WINDOW_UPDATE diverges too.
    assert!(divs
        .iter()
        .any(|d| matches!(d, AkamaiH2Divergence::WindowUpdate { .. })));
}

#[test]
fn identical_shapes_have_empty_diff_and_match() {
    let ff = AkamaiH2Fingerprint::parse(lookup("firefox-150-linux").unwrap().akamai_h2).unwrap();
    let ff2 = ff.clone();
    assert!(ff.diff(&ff2).is_empty());
    assert!(ff.matches(&ff2));
}

#[test]
fn settings_order_only_divergence_is_reported_as_order_not_value() {
    // Same id:value set, different sent order.
    let a = AkamaiH2Fingerprint::parse("1:65536;4:131072|0|0|m").unwrap();
    let b = AkamaiH2Fingerprint::parse("4:131072;1:65536|0|0|m").unwrap();
    let divs = a.diff(&b);
    assert_eq!(divs.len(), 1, "only the order should differ: {divs:?}");
    assert!(matches!(
        &divs[0],
        AkamaiH2Divergence::SettingsOrder { observed, target }
            if observed == &vec![1u16, 4] && target == &vec![4u16, 1]
    ));
    assert!(!a.matches(&b));
}

#[test]
fn pseudo_header_codes_round_trip() {
    assert_eq!(PseudoHeader::Method.code(), 'm');
    assert_eq!(PseudoHeader::Path.code(), 'p');
    assert_eq!(PseudoHeader::Authority.code(), 'a');
    assert_eq!(PseudoHeader::Scheme.code(), 's');
}

// ─── Fail-closed parse errors ────────────────────────────────────────────────

#[test]
fn wrong_section_count_fails() {
    assert_eq!(
        AkamaiH2Fingerprint::parse("1:65536|0|0"),
        Err(AkamaiH2ParseError::SectionCount(3))
    );
    assert_eq!(
        AkamaiH2Fingerprint::parse("1:65536|0|0|m|extra"),
        Err(AkamaiH2ParseError::SectionCount(5))
    );
}

#[test]
fn malformed_setting_token_fails() {
    // No colon.
    assert!(matches!(
        AkamaiH2Fingerprint::parse("65536|0|0|m"),
        Err(AkamaiH2ParseError::Settings(_))
    ));
    // Non-numeric id.
    assert!(matches!(
        AkamaiH2Fingerprint::parse("x:65536|0|0|m"),
        Err(AkamaiH2ParseError::Settings(_))
    ));
    // Value overflows u32.
    assert!(matches!(
        AkamaiH2Fingerprint::parse("1:99999999999|0|0|m"),
        Err(AkamaiH2ParseError::Settings(_))
    ));
}

#[test]
fn malformed_window_update_fails() {
    assert!(matches!(
        AkamaiH2Fingerprint::parse("1:65536|notanumber|0|m"),
        Err(AkamaiH2ParseError::WindowUpdate(_))
    ));
}

#[test]
fn malformed_priority_frame_fails() {
    // Three fields instead of four.
    assert!(matches!(
        AkamaiH2Fingerprint::parse("1:65536|0|3:0:201|m"),
        Err(AkamaiH2ParseError::Priority(_))
    ));
    // Non-numeric weight.
    assert!(matches!(
        AkamaiH2Fingerprint::parse("1:65536|0|3:0:0:hi|m"),
        Err(AkamaiH2ParseError::Priority(_))
    ));
}

#[test]
fn malformed_pseudo_header_fails() {
    // Unknown code.
    assert!(matches!(
        AkamaiH2Fingerprint::parse("1:65536|0|0|m,x"),
        Err(AkamaiH2ParseError::PseudoHeader(_))
    ));
    // Multi-char token.
    assert!(matches!(
        AkamaiH2Fingerprint::parse("1:65536|0|0|method"),
        Err(AkamaiH2ParseError::PseudoHeader(_))
    ));
    // Empty pseudo section.
    assert!(matches!(
        AkamaiH2Fingerprint::parse("1:65536|0|0|"),
        Err(AkamaiH2ParseError::PseudoHeader(_))
    ));
}

#[test]
fn empty_settings_section_is_allowed() {
    // A client that sent no SETTINGS values (rare but legal) parses to an empty
    // settings vec, and round-trips.
    let fp = AkamaiH2Fingerprint::parse("|0|0|m,p,a,s").unwrap();
    assert!(fp.settings.is_empty());
    assert_eq!(fp.to_canonical(), "|0|0|m,p,a,s");
}
