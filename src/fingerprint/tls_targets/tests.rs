use super::*;

#[test]
fn ships_three_measured_targets() {
    // After removing the hand-copied approximate entries, the built-in catalogue
    // contains only targets captured from real ClientHellos on this fleet.
    assert_eq!(
        FINGERPRINT_TARGETS.len(),
        3,
        "built-in catalogue must contain exactly the three measured targets"
    );
}

#[test]
fn every_label_resolves_via_lookup() {
    for target in FINGERPRINT_TARGETS {
        let resolved = lookup(target.label).expect("label must round-trip");
        assert_eq!(resolved, target);
    }
}

#[test]
fn lookup_returns_none_for_unknown_label() {
    assert!(lookup("internet-explorer-6").is_none());
    assert!(lookup("").is_none());
    assert!(
        lookup("chrome-130-win").is_none(),
        "lookup is exact and the old approximate target was removed"
    );
    assert!(
        lookup("CHROME-146-LINUX").is_none(),
        "lookup is case-sensitive"
    );
}

#[test]
fn every_published_target_has_a_coherent_tcp_companion() {
    // G022/G051 cross-catalogue coherence: the published per-label TLS/H2 target
    // catalogue (this module) and the os_network TCP catalogue (guise-profiles)
    // must agree on OS. Every target's label-OS must have a modeled TCP/IP stack,
    // and that stack must render a well-formed, fail-closed JA4T whose window
    // shape is itself coherent with the OS family, so a target added for an OS we
    // do not model on the TCP layer (a partial, incoherent persona) fails here.
    // The four strings (JA3, JA4, Akamai-H2, JA4T) are the full network
    // fingerprint G051 calls for, assembled for one OS.
    use crate::fingerprint::{os_network_stack, UserAgentPlatform};

    fn os_from_label(label: &str) -> Option<UserAgentPlatform> {
        label.split('-').find_map(|seg| match seg {
            "win" => Some(UserAgentPlatform::Windows),
            "mac" => Some(UserAgentPlatform::MacOs),
            "linux" => Some(UserAgentPlatform::Linux),
            "ios" => Some(UserAgentPlatform::Ios),
            "android" => Some(UserAgentPlatform::Android),
            _ => None,
        })
    }

    for target in FINGERPRINT_TARGETS {
        let os = os_from_label(target.label)
            .unwrap_or_else(|| panic!("{}: label carries no OS segment", target.label));
        let stack = os_network_stack(os)
            .unwrap_or_else(|| panic!("{}: OS {os:?} has no modeled TCP/IP stack", target.label));

        // The TCP companion renders a faithful, fail-closed JA4T (four
        // underscore-separated fields).
        let ja4t = stack
            .ja4t()
            .unwrap_or_else(|e| panic!("{}: JA4T failed closed: {e}", target.label));
        assert_eq!(
            ja4t.matches('_').count(),
            3,
            "{}: malformed JA4T {ja4t}",
            target.label
        );

        // OS ↔ JA4T window-shape coherence: autotuned-window OS families wildcard
        // the window; fixed-window families carry a concrete numeric window. A
        // mis-keyed stack (e.g. a Windows label resolving to the Linux stack)
        // breaks this.
        let window_field = ja4t.split('_').next().unwrap();
        match os {
            UserAgentPlatform::Linux | UserAgentPlatform::Android => assert_eq!(
                window_field, "*",
                "{}: autotuned OS {os:?} must wildcard the JA4T window",
                target.label
            ),
            _ => assert!(
                window_field.parse::<u16>().is_ok(),
                "{}: fixed-window OS {os:?} must carry a numeric JA4T window, got {window_field}",
                target.label
            ),
        }

        // p0f descriptive companion renders too, and the full four-layer network
        // fingerprint is present for this target.
        assert!(
            !stack.p0f_signature().is_empty(),
            "{}: empty p0f signature",
            target.label
        );
        assert!(
            !target.ja3.is_empty() && !target.ja4.is_empty() && !target.akamai_h2.is_empty(),
            "{}: incomplete TLS/H2 fingerprint set",
            target.label
        );
    }
}

#[test]
fn every_target_has_non_empty_fields() {
    for target in FINGERPRINT_TARGETS {
        assert!(!target.label.is_empty(), "target label empty");
        assert!(!target.ja3.is_empty(), "{}: empty JA3", target.label);
        assert!(!target.ja4.is_empty(), "{}: empty JA4", target.label);
        assert!(
            !target.akamai_h2.is_empty(),
            "{}: empty akamai_h2",
            target.label
        );
        assert!(
            !target.peet_h2.is_empty(),
            "{}: empty peet_h2",
            target.label
        );
    }
}

#[test]
fn all_labels_lists_every_target_in_order() {
    let labels = all_labels();
    assert_eq!(labels.len(), FINGERPRINT_TARGETS.len());
    for (index, target) in FINGERPRINT_TARGETS.iter().enumerate() {
        assert_eq!(labels[index], target.label);
    }
}

#[test]
fn ja3_format_starts_with_tls_version_771() {
    for target in FINGERPRINT_TARGETS {
        assert!(
            target.ja3.starts_with("771,"),
            "{}: JA3 must start with 771, got {}",
            target.label,
            &target.ja3[..target.ja3.len().min(20)]
        );
    }
}

#[test]
fn ja4_format_starts_with_t13d_for_tls_13_targets() {
    for target in FINGERPRINT_TARGETS {
        assert!(
            target.ja4.starts_with("t13d"),
            "{}: JA4 must start with t13d, got {}",
            target.label,
            &target.ja4[..target.ja4.len().min(8)]
        );
    }
}

#[test]
fn akamai_h2_has_pipe_separated_four_part_format() {
    for target in FINGERPRINT_TARGETS {
        let parts: Vec<&str> = target.akamai_h2.split('|').collect();
        assert_eq!(
            parts.len(),
            4,
            "{}: akamai_h2 must have 4 pipe-separated parts, got {}",
            target.label,
            parts.len()
        );
    }
}

#[test]
fn every_target_h2_pseudo_header_order_matches_its_browser_family() {
    // X-series transport coherence (M3). A target's `label` names the browser
    // family (chrome/firefox) and its `akamai_h2` pseudo-header order ENCODES
    // that family, these are distinct wire signals a cross-checking anti-bot
    // reads together. Real, measured per-family orders (peet.ws / Akamai H2):
    // Chrome `:method,:authority,:scheme,:path`; Firefox
    // `:method,:path,:authority,:scheme`. If a `firefox-*` target carried
    // Chrome's `m,a,s,p`, the TLS layer would say Firefox while the HEADERS
    // frame says Chrome (the loudest possible transport-vs-transport split).
    // Parsed via the structured `AkamaiH2Fingerprint` (no string-splitting), and
    // fail-CLOSED on any label whose family this gate does not know (an
    // unclassifiable target must extend this fence, never slip through. Law 10).
    use crate::fingerprint::akamai_h2::{AkamaiH2Fingerprint, PseudoHeader};
    use PseudoHeader::{Authority, Method, Path, Scheme};

    fn expected_order(label: &str) -> Vec<PseudoHeader> {
        if label.starts_with("chrome-") {
            vec![Method, Authority, Scheme, Path]
        } else if label.starts_with("firefox-") {
            vec![Method, Path, Authority, Scheme]
        } else {
            panic!(
                "{label}: H2-coherence gate does not know this browser family. \
                 extend `expected_order` with its canonical pseudo-header order \
                 (do NOT let an unclassified target bypass the fence)"
            );
        }
    }

    for target in FINGERPRINT_TARGETS {
        let parsed = AkamaiH2Fingerprint::parse(target.akamai_h2).unwrap_or_else(|e| {
            panic!(
                "{}: akamai_h2 {:?} failed to parse: {e:?}",
                target.label, target.akamai_h2
            )
        });
        assert_eq!(
            parsed.pseudo_header_order,
            expected_order(target.label),
            "{}: H2 pseudo-header order {:?} does not match the order for its labeled \
             browser family (from akamai_h2 {:?})",
            target.label,
            parsed
                .pseudo_header_order
                .iter()
                .map(|p| p.code())
                .collect::<String>(),
            target.akamai_h2,
        );
    }
}

#[test]
fn every_target_h2_settings_profile_matches_its_browser_family() {
    // Companion to the pseudo-header gate: the SETTINGS frame independently encodes
    // the browser family, so a target is fenced on TWO orthogonal H2 signals. Real,
    // measured across shipped targets: Firefox sends SETTINGS_MAX_FRAME_SIZE
    // (id 5) and NEVER MAX_HEADER_LIST_SIZE (id 6); Chrome the inverse (id 6, never
    // id 5). These two cases are mutually exclusive, so a `firefox-*` target
    // accidentally carrying Chrome's SETTINGS (id 6, no id 5) is caught here even
    // when its pseudo-header order looks right. Read via the typed
    // `max_frame_size`/`max_header_list_size` accessors (no string parse),
    // fail-CLOSED on an unknown family (must extend the fence. Law 10).
    use crate::fingerprint::akamai_h2::AkamaiH2Fingerprint;

    for target in FINGERPRINT_TARGETS {
        let p = AkamaiH2Fingerprint::parse(target.akamai_h2)
            .unwrap_or_else(|e| panic!("{}: akamai_h2 failed to parse: {e:?}", target.label));
        let has_max_frame = p.max_frame_size().is_some(); // id 5
        let has_max_header_list = p.max_header_list_size().is_some(); // id 6
        let (want_frame, want_header_list) = if target.label.starts_with("chrome-") {
            (false, true)
        } else if target.label.starts_with("firefox-") {
            (true, false)
        } else {
            panic!(
                "{}: H2-SETTINGS-coherence gate does not know this browser family. \
                 extend it with the family's measured (max_frame_size, max_header_list_size) \
                 presence (do NOT let an unclassified target bypass the fence)",
                target.label
            );
        };
        assert_eq!(
            (has_max_frame, has_max_header_list),
            (want_frame, want_header_list),
            "{}: H2 SETTINGS family shape (max_frame_size present={has_max_frame}, \
             max_header_list_size present={has_max_header_list}) does not match its labeled \
             browser family's measured profile (from akamai_h2 {:?})",
            target.label,
            target.akamai_h2
        );
    }
}

#[test]
fn every_target_peet_h2_is_the_real_md5_of_its_akamai_h2() {
    // Integrity guard, twin of `chrome_tls::every_snapshot_ja3_hash_is_the_real_
    // md5_of_its_ja3_string`. peet.ws reports `http2.akamai_fingerprint_hash` as
    // md5(`http2.akamai_fingerprint`), by definition. So a target's `peet_h2`
    // that is not md5(its own `akamai_h2`) is fabricated/drifted data that real
    // peet.ws could NEVER emit for that H2 string. This locks every entry's peet
    // hash to its own H2 bytes so the catalogue can never again ship a transport
    // hash that lies about what it fingerprints.
    for target in FINGERPRINT_TARGETS {
        let real = crate::fingerprint::ja3::md5_string(target.akamai_h2);
        assert_eq!(
            target.peet_h2, real,
            "{}: stored peet_h2 {} is not md5(akamai_h2); real md5 of {:?} is {}",
            target.label, target.peet_h2, target.akamai_h2, real
        );
    }
}

#[test]
fn every_builtin_target_passes_the_shared_validator() {
    // The built-in catalogue and the Tier-B loader validate through ONE
    // function (so a built-in that the loader would reject can't slip in).
    for t in FINGERPRINT_TARGETS {
        validate_target_fields(t.label, t.ja3, t.ja4, t.akamai_h2, t.peet_h2)
            .unwrap_or_else(|e| panic!("built-in {} fails the loader's validator: {e}", t.label));
    }
}

#[test]
fn builtin_with_appends_extra_after_builtins() {
    let extra = [FingerprintTarget {
        label: "synthetic-extra",
        ja3: "771,4865,0,29,0",
        ja4: "t13d0101h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
        akamai_h2: "1:1|2|3|m",
        peet_h2: "deadbeef",
    }];
    let merged = builtin_with(&extra);
    assert_eq!(merged.len(), FINGERPRINT_TARGETS.len() + 1);
    assert_eq!(merged[0].label, FINGERPRINT_TARGETS[0].label);
    assert_eq!(merged.last().unwrap().label, "synthetic-extra");
}

// ── JA3/JA4 count consistency ───────────────────────────────────────────────

#[test]
fn every_builtin_target_is_ja3_ja4_count_consistent() {
    // Fail-closed catalogue guard: a shipped target whose JA4 cipher/extension
    // counts disagree with its own JA3 lists is internally inconsistent and
    // cannot be trusted as a cluster reference. Removing the old approximate
    // entries turned this from an allow-list into a universal property.
    for target in FINGERPRINT_TARGETS {
        ja4_counts_match_ja3(target.ja3, target.ja4)
            .unwrap_or_else(|e| panic!("{} JA3/JA4 counts disagree: {e}", target.label));
    }
}

#[test]
fn measured_firefox_150_target_is_ja3_ja4_count_consistent() {
    // Explicit anchor for the reynard persona: 17 ciphers / 17 extensions,
    // JA4 `t13d1717h2`.
    let ff = lookup("firefox-150-linux").expect("ff-150 must ship");
    ja4_counts_match_ja3(ff.ja3, ff.ja4)
        .unwrap_or_else(|e| panic!("firefox-150-linux JA3/JA4 counts disagree: {e}"));
}

#[test]
fn ja4_counts_match_ja3_detects_mismatched_counts() {
    // Negative twin: the predicate must catch a fabricated JA4 count.
    let ja3 = "771,4865-4866,0-23-65281,29,0"; // 2 ciphers, 3 extensions
    let ja4_ok = "t13d0203h2_aaaaaaaaaaaa_bbbbbbbbbbbb";
    assert!(ja4_counts_match_ja3(ja3, ja4_ok).is_ok());

    let ja4_bad_cipher = "t13d0303h2_aaaaaaaaaaaa_bbbbbbbbbbbb";
    assert!(ja4_counts_match_ja3(ja3, ja4_bad_cipher).is_err());

    let ja4_bad_ext = "t13d0202h2_aaaaaaaaaaaa_bbbbbbbbbbbb";
    assert!(ja4_counts_match_ja3(ja3, ja4_bad_ext).is_err());
}

#[test]
fn ja4_counts_match_ja3_rejects_malformed_inputs() {
    assert!(ja4_counts_match_ja3("not,five,fields", "t13d0202h2_x_y").is_err());
    assert!(ja4_counts_match_ja3("771,1,2,3,0", "short").is_err());
    assert!(ja4_counts_match_ja3("771,1,2,3,0", "t13dxx02h2_x_y").is_err());
}

#[test]
fn validator_rejects_each_malformed_field() {
    // A well-formed Akamai H2 baseline so each line isolates the ONE field
    // under test. The Akamai field now parses for real (not a 4-pipe sniff),
    // so a placeholder like `a|b|c|d` is itself rejected.
    let ok = "1:65536|0|0|m,p,a,s";
    assert!(
        validate_target_fields("", "771,x", "t13", ok, "h").is_err(),
        "empty label"
    );
    assert!(
        validate_target_fields("l", "770,x", "t13", ok, "h").is_err(),
        "bad JA3 version"
    );
    assert!(
        validate_target_fields("l", "771,x", "t12", ok, "h").is_err(),
        "non-TLS1.3 JA4"
    );
    // Akamai rejections, each via the structured parser:
    assert!(
        validate_target_fields("l", "771,x", "t13", "a|b|c", "h").is_err(),
        "3 sections"
    );
    assert!(
        validate_target_fields("l", "771,x", "t13", "nope|0|0|m", "h").is_err(),
        "bad SETTINGS"
    );
    assert!(
        validate_target_fields("l", "771,x", "t13", "1:65536|0|0|x", "h").is_err(),
        "bad pseudo-header"
    );
    assert!(
        validate_target_fields("l", "771,x", "t13", ok, "").is_err(),
        "empty peetprint"
    );
    assert!(
        validate_target_fields("l", "771,x", "t13", ok, "deadbeefdeadbeefdeadbeefdeadbeef")
            .is_err(),
        "non-empty peet_h2 that is not md5(akamai_h2) is fabricated → rejected"
    );
    // The real md5 of the `ok` akamai string (the ONLY peet_h2 the validator accepts).
    let ok_peet = crate::fingerprint::ja3::md5_string(ok);
    assert!(
        validate_target_fields("l", "771,x", "t13", ok, &ok_peet).is_ok(),
        "all fields valid (peet_h2 == md5(akamai_h2))"
    );
}
