//! Unit tests for [`super`]. JA3/JA4 string + hash construction and the GREASE/order invariants.

use super::*;

fn chrome_130_fields() -> ClientHelloFields {
    ClientHelloFields {
        version: 771,
        cipher_suites: vec![
            4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47,
            53,
        ],
        extensions: vec![
            0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21,
        ],
        supported_groups: vec![29, 23, 24],
        ec_point_formats: vec![0],
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        signature_algorithms: vec![0x0403, 0x0804, 0x0401],
        // Real Chrome offers TLS 1.3 + 1.2 in supported_versions despite the
        // legacy version field being pinned to 0x0303.
        supported_versions: vec![0x0304, 0x0303],
    }
}

#[test]
fn compute_ja3_returns_canonical_format() {
    let fields = chrome_130_fields();
    let ja3 = compute_ja3(&fields);
    let parts: Vec<&str> = ja3.split(',').collect();
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[0], "771");
    assert!(parts[1].contains("4865"));
    assert!(parts[2].contains("65281"));
    assert!(parts[3].contains("29"));
    assert_eq!(parts[4], "0");
}

#[test]
fn compute_ja3_strips_grease_values() {
    let mut fields = chrome_130_fields();
    fields.cipher_suites.insert(0, 0x0a0a);
    fields.cipher_suites.push(0x1a1a);
    fields.extensions.insert(0, 0x2a2a);
    let ja3 = compute_ja3(&fields);
    assert!(!ja3.contains("0a0a"), "GREASE 0a0a should be stripped");
    assert!(!ja3.contains("2a2a"), "GREASE 2a2a should be stripped");
    assert!(
        !ja3.contains("2570"),
        "GREASE 0x0a0a decimal form should be stripped"
    );
}

#[test]
fn compute_ja3_hash_is_md5_of_canonical() {
    let fields = ClientHelloFields {
        version: 771,
        cipher_suites: vec![],
        extensions: vec![],
        supported_groups: vec![],
        ec_point_formats: vec![],
        alpn: vec![],
        signature_algorithms: vec![],
        supported_versions: vec![],
    };
    let canonical = compute_ja3(&fields);
    assert_eq!(canonical, "771,,,,");
    let via_path = compute_ja3_hash(&fields);
    let via_oracle = md5_string(&canonical);
    assert_eq!(via_path, via_oracle);
    assert_eq!(via_path.len(), 32);
    assert!(via_path.chars().all(|char| char.is_ascii_hexdigit()));
}

#[test]
fn ja3_hash_changes_when_cipher_order_changes() {
    let first = ClientHelloFields {
        version: 771,
        cipher_suites: vec![4865, 4866],
        extensions: vec![0],
        supported_groups: vec![29],
        ec_point_formats: vec![0],
        alpn: vec![],
        signature_algorithms: vec![],
        supported_versions: vec![],
    };
    let second = ClientHelloFields {
        version: 771,
        cipher_suites: vec![4866, 4865],
        extensions: vec![0],
        supported_groups: vec![29],
        ec_point_formats: vec![0],
        alpn: vec![],
        signature_algorithms: vec![],
        supported_versions: vec![],
    };
    assert_ne!(compute_ja3_hash(&first), compute_ja3_hash(&second));
}

#[test]
fn verify_against_target_returns_match_when_canonical_string_equals() {
    let fields = chrome_130_fields();
    let target = compute_ja3(&fields);
    let outcome = verify_against_target(&fields, &target);
    assert!(outcome.is_match());
}

#[test]
fn verify_against_target_returns_drift_with_both_strings() {
    let fields = chrome_130_fields();
    let outcome = verify_against_target(&fields, "771,4865,,,0");
    match outcome {
        JA3VerificationOutcome::Drift { actual, expected } => {
            assert_eq!(expected, "771,4865,,,0");
            assert!(actual.starts_with("771,"));
        }
        JA3VerificationOutcome::Match { .. } => panic!("expected Drift"),
    }
}

#[test]
fn ja4_version_comes_from_supported_versions_not_the_legacy_field() {
    // chrome_130_fields pins the legacy version to 0x0303 (TLS 1.2) but offers
    // TLS 1.3 in supported_versions, exactly as a real browser does. JA4 must
    // report the NEGOTIATED version (t13), not the spoofable legacy field
    // this is the value reynard/stock FF actually emit on the wire (t13...).
    let fields = chrome_130_fields();
    assert_eq!(fields.version, 771, "legacy field is TLS 1.2 for compat");
    let ja4 = compute_ja4(&fields);
    assert!(
        ja4.starts_with("t13d"),
        "JA4 must take the TLS 1.3 from supported_versions, got {ja4}"
    );
}

#[test]
fn ja4_falls_back_to_legacy_version_when_no_supported_versions() {
    // No supported_versions extension (older/non-browser client): JA4 uses the
    // legacy ClientHello version field, the FoxIO-spec fallback, not a silent
    // default. A legacy-771 client with no extension is genuinely t12.
    let fields = chrome_130_fields().with_supported_versions(vec![]);
    assert!(fields.supported_versions.is_empty());
    let ja4 = compute_ja4(&fields);
    assert!(
        ja4.starts_with("t12d"),
        "JA4 must fall back to the legacy version 771 (t12), got {ja4}"
    );
}

#[test]
fn effective_tls_version_prefers_supported_versions_max_stripping_grease() {
    // The resolver takes the highest non-GREASE supported version, ignoring a
    // GREASE entry a browser may prepend.
    let fields = chrome_130_fields().with_supported_versions(vec![0x6a6a, 0x0304, 0x0303]);
    assert_eq!(fields.effective_tls_version(), 0x0304);
    // Empty → legacy field.
    let legacy = chrome_130_fields().with_supported_versions(vec![]);
    assert_eq!(legacy.effective_tls_version(), 771);
}

#[test]
fn ja4_filters_grease_from_cipher_count() {
    let mut fields = chrome_130_fields();
    let baseline = compute_ja4(&fields);
    fields.cipher_suites.insert(0, 0x0a0a);
    fields.cipher_suites.push(0x1a1a);
    let with_grease = compute_ja4(&fields);
    assert_eq!(baseline, with_grease);
}

#[test]
fn is_grease_recognises_all_sixteen_grease_values() {
    for value in GREASE_VALUES {
        assert!(is_grease(value));
    }
    assert!(!is_grease(4865));
    assert!(!is_grease(0));
    assert!(!is_grease(0x0a0b));
}

/// The real, measured Firefox-150 / Linux ClientHello fields (from the
/// `tls.peet.ws` capture that backs the `firefox-150-linux` catalogue target):
/// 17 ciphers, 17 extensions (incl. SNI `0` and ALPN `16`).
fn firefox_150_fields() -> ClientHelloFields {
    ClientHelloFields {
        version: 771,
        cipher_suites: vec![
            4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172,
            156, 157, 47, 53,
        ],
        extensions: vec![
            0, 23, 65281, 10, 11, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037, 41,
        ],
        supported_groups: vec![4588, 29, 23, 24, 25, 256, 257],
        ec_point_formats: vec![0],
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        // Firefox's real signature_algorithms list (11 entries): the 9 modern
        // ECDSA/RSA-PSS/RSA-PKCS1 algorithms followed by the two legacy SHA-1
        // algorithms (ecdsa_sha1 0x0203, rsa_pkcs1_sha1 0x0201) that Firefox still
        // advertises. Omitting the SHA-1 pair (as the simplified `FIREFOX_SIG_ALGS`
        // catalogue did) yields the wrong JA4 extension hash.
        signature_algorithms: vec![
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
        ],
        supported_versions: vec![0x0304, 0x0303],
    }
}

#[test]
fn ja4_extension_count_includes_sni_and_alpn() {
    // FoxIO JA4: the _a extension COUNT includes SNI (0x0000) and ALPN (0x0010);
    // only the sorted _c HASH excludes them. A list of [SNI, ALPN, one real ext]
    // must therefore count as 3, not 1. (Regression for the count-from-filtered bug
    // that produced `…15h2` where a real FF-150 emits `…17h2`.)
    let fields = ClientHelloFields {
        version: 771,
        cipher_suites: vec![4865],
        extensions: vec![0x0000, 0x0010, 0x0017],
        supported_groups: vec![29],
        ec_point_formats: vec![0],
        alpn: vec![b"h2".to_vec()],
        signature_algorithms: vec![0x0403],
        supported_versions: vec![0x0304],
    };
    let ja4 = compute_ja4(&fields);
    // t13 d 01(cipher) 03(ext) h2 (three extensions counted, SNI+ALPN included).
    assert!(
        ja4.starts_with("t13d0103h2_"),
        "extension count must include SNI+ALPN (expected 03), got {ja4}"
    );
}

#[test]
fn ja3_and_ja4_for_firefox_150_match_the_measured_wire_values() {
    // G110 / G111 unit vectors: guise's JA3/JA4 computation reproduces the real,
    // peet-measured Firefox-150 wire fingerprint (the values backing the
    // `firefox-150-linux` catalogue target).
    let f = firefox_150_fields();

    // G110, the JA3 hash matches the measured value EXACTLY: guise's JA3 string
    // construction + MD5 reproduce a real browser's JA3 from its ClientHello.
    assert_eq!(
        compute_ja3_hash(&f),
        "0e76c7e9d06fa0e211b1827687dd8f43",
        "JA3 hash must reproduce the measured FF-150 value"
    );

    // G111, the full JA4 matches byte-for-byte: protocol/version/SNI, cipher +
    // extension counts, cipher hash, AND the signature-algorithms-dependent
    // extension hash. The match holds only once the fixture carries Firefox's real
    // 11-entry sig-algs list (the two trailing SHA-1 algorithms included), which
    // is exactly how the `FIREFOX_SIG_ALGS` catalogue bug was found.
    assert_eq!(
        compute_ja4(&f),
        "t13d1717h2_5b57614c22b0_e6dcd7ae0a9e",
        "JA4 must reproduce the measured FF-150 value (incl. the sig-algs-dependent ext hash)"
    );
}

#[test]
fn ja4_sni_indicator_is_d_with_server_name_extension_and_i_without() {
    // FoxIO JA4: `d` when SNI (extension 0x0000) is present, `i` otherwise.
    // Browser personas always send SNI → `d`; a no-SNI handshake must report `i`.
    let with_sni = firefox_150_fields(); // extensions include 0x0000
    assert!(
        compute_ja4(&with_sni).starts_with("t13d"),
        "SNI present must yield `d`"
    );
    let mut without_sni = firefox_150_fields();
    without_sni.extensions.retain(|&e| e != 0x0000);
    let ja4 = compute_ja4(&without_sni);
    assert!(
        ja4.starts_with("t13i"),
        "no SNI extension must yield `i`, got {ja4}"
    );
    // Dropping SNI also drops the extension count by one (16 now), but the hash
    // already excluded SNI so the _c hash is unchanged, only the `d`→`i` and the
    // count move.
    assert!(ja4.starts_with("t13i1716h2_"), "got {ja4}");
}

#[test]
fn ja4_for_firefox_150_has_the_measured_seventeen_seventeen_prefix() {
    // The canonical (peet-measured) FF-150 JA4 _a section is `t13d1717h2`:
    // 17 ciphers, 17 extensions (SNI+ALPN counted), TLS 1.3, SNI present, ALPN h2.
    // guise's compute_ja4 must agree on that prefix or it emits a JA4 that no real
    // Firefox produces, a fingerprint tell. (The two 12-hex hash halves depend on
    // exact sig-alg/sort handling and are asserted structurally, not byte-pinned,
    // here.)
    let ja4 = compute_ja4(&firefox_150_fields());
    assert!(
        ja4.starts_with("t13d1717h2_"),
        "FF-150 JA4 _a must be t13d1717h2 (17 ciphers, 17 extensions incl. SNI+ALPN), got {ja4}"
    );
    let parts: Vec<&str> = ja4.split('_').collect();
    assert_eq!(
        parts.len(),
        3,
        "JA4 has three underscore-separated parts: {ja4}"
    );
    assert_eq!(parts[1].len(), 12, "cipher hash is 12 hex chars: {ja4}");
    assert_eq!(parts[2].len(), 12, "extension hash is 12 hex chars: {ja4}");
    assert!(
        parts[1]
            .chars()
            .chain(parts[2].chars())
            .all(|c| c.is_ascii_hexdigit()),
        "JA4 hash halves must be hex: {ja4}"
    );
}

#[test]
fn md5_string_matches_known_oracle_for_empty_input() {
    assert_eq!(md5_string(""), "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn md5_string_matches_known_oracle_for_short_input() {
    assert_eq!(md5_string("a"), "0cc175b9c0f1b6a831c399e269772661");
    assert_eq!(md5_string("abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        md5_string("message digest"),
        "f96b697d7cb7938d525a2f31aaf161d0"
    );
}

#[test]
fn ja3_known_good_vector_for_chrome() {
    // G110 known-good vector: the structured Chrome ClientHello (with the
    // 17513 application-settings extension) must render to the exact canonical
    // JA3 string and the exact MD5 hash a real Chrome 134 emits. This is the
    // same string+hash the `chrome_tls` catalogue ships for Chrome 134/Linux,
    // so the builder, the hash, and the catalogue are all locked to one value.
    let fields = chrome_130_fields();
    assert_eq!(
        compute_ja3(&fields),
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
             0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
    );
    assert_eq!(
        compute_ja3_hash(&fields),
        "cd08e31494f9531f560d64c695473da9",
        "JA3 hash drifted from the known-good Chrome value"
    );
}

#[test]
fn ja4_cipher_hash_matches_known_chrome_reference() {
    // G111 known-good vector (the unambiguous part): the JA4 cipher-hash
    // segment is sha256-first-12 of the GREASE-stripped, ascending-sorted
    // Chrome cipher list, independent of the version/SNI/count nuances. It
    // must equal `8daaf6152771`, the value BOTH the FoxIO-spec independent
    // derivation AND every `chrome_tls` catalogue JA4 string carry, locking
    // the cipher-hash computation to real reference data.
    let fields = chrome_130_fields();
    let ja4 = compute_ja4(&fields);
    let segments: Vec<&str> = ja4.split('_').collect();
    assert_eq!(
        segments.len(),
        3,
        "JA4 must have 3 underscore-separated segments: {ja4}"
    );
    assert_eq!(
        segments[1], "8daaf6152771",
        "JA4 cipher hash drifted from the known Chrome reference"
    );
    // The cross-check against shipped catalogue data: the same 15-cipher
    // Chrome list appears in the catalogue, so its JA4 cipher segment matches.
    let catalogue_cipher_hash = crate::fingerprint::chrome_tls::CHROME_FINGERPRINTS[0]
        .ja4
        .split('_')
        .nth(1)
        .expect("catalogue JA4 has a cipher-hash segment");
    assert_eq!(
        segments[1], catalogue_cipher_hash,
        "computed JA4 cipher hash disagrees with the chrome_tls catalogue"
    );
    for segment in [segments[1], segments[2]] {
        assert_eq!(segment.len(), 12, "JA4 hash segment must be 12 hex chars");
        assert!(segment.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

proptest::proptest! {
    #[test]
    fn compute_ja3_never_panics(
        version in proptest::prelude::any::<u16>(),
        ciphers in proptest::collection::vec(proptest::prelude::any::<u16>(), 0..40),
        extensions in proptest::collection::vec(proptest::prelude::any::<u16>(), 0..40),
        groups in proptest::collection::vec(proptest::prelude::any::<u16>(), 0..20),
        point_formats in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..6),
    ) {
        let fields = ClientHelloFields {
            version,
            cipher_suites: ciphers,
            extensions,
            supported_groups: groups,
            ec_point_formats: point_formats,
            alpn: vec![],
            signature_algorithms: vec![],
            supported_versions: vec![],
        };
        let canonical = compute_ja3(&fields);
        let hash = compute_ja3_hash(&fields);
        proptest::prop_assert_eq!(hash.len(), 32);
        proptest::prop_assert!(hash.chars().all(|char| char.is_ascii_hexdigit()));
        proptest::prop_assert_eq!(canonical.split(',').count(), 5);
    }

    #[test]
    fn compute_ja4_never_panics(
        version in proptest::prelude::any::<u16>(),
        ciphers in proptest::collection::vec(proptest::prelude::any::<u16>(), 0..40),
        extensions in proptest::collection::vec(proptest::prelude::any::<u16>(), 0..40),
        sigalgs in proptest::collection::vec(proptest::prelude::any::<u16>(), 0..16),
        alpn_strs in proptest::collection::vec("[a-zA-Z0-9./_-]{0,16}", 0..4),
    ) {
        let fields = ClientHelloFields {
            version,
            cipher_suites: ciphers,
            extensions,
            supported_groups: vec![],
            ec_point_formats: vec![],
            alpn: alpn_strs.iter().map(|s| s.as_bytes().to_vec()).collect::<Vec<_>>(),
            signature_algorithms: sigalgs,
            supported_versions: vec![],
        };
        let ja4 = compute_ja4(&fields);
        proptest::prop_assert!(ja4.starts_with('t'),
            "JA4 must start with transport char 't': {ja4}");
        proptest::prop_assert_eq!(ja4.matches('_').count(), 2);
    }

    #[test]
    fn ja4_unknown_version_does_not_collide_with_tls13(
        ciphers in proptest::collection::vec(proptest::prelude::any::<u16>(), 0..20),
    ) {
        let fields = ClientHelloFields {
            version: 0xABCD,
            cipher_suites: ciphers,
            extensions: vec![],
            supported_groups: vec![],
            ec_point_formats: vec![],
            alpn: vec![],
            signature_algorithms: vec![],
            supported_versions: vec![],
        };
        let ja4 = compute_ja4(&fields);
        proptest::prop_assert!(ja4.starts_with("t00"),
            "unknown TLS version must emit t00 sentinel: {ja4}");
    }
}
