//! Shape validation for fingerprint targets, the single source of truth shared
//! by the built-in catalogue audit and the Tier-B loader (no duplicated format
//! checks). Split out of `tls_targets` to keep each file under the Law-5 limit.

/// Validate the shape of one target's fingerprint fields, the single source of
/// truth shared by the built-in catalogue audit and the Tier-B loader (no
/// duplicated format checks). Returns the reason string on the first violation.
///
/// Checks: non-empty label; JA3 starts with the TLS-version token `771,`; JA4
/// starts with `t13` (a TLS 1.3 target); Akamai-H2 parses as a structured
/// [`akamai_h2::AkamaiH2Fingerprint`](crate::fingerprint::akamai_h2) (every
/// SETTINGS/PRIORITY/pseudo-header section well-formed); peetprint is non-empty
/// AND equals `md5(akamai_h2)`: peet.ws derives `akamai_fingerprint_hash` as the
/// MD5 of the akamai string, so a `peet_h2` that is not that md5 is fabricated
/// data real peet.ws could never emit, and is refused at this boundary (built-in
/// audit + Tier-B load) rather than silently shipped.
///
/// # Errors
/// Returns `Err(reason)` describing the first malformed field.
pub fn validate_target_fields(
    label: &str,
    ja3: &str,
    ja4: &str,
    akamai_h2: &str,
    peet_h2: &str,
) -> Result<(), String> {
    if label.is_empty() {
        return Err("empty label".to_string());
    }
    if !ja3.starts_with("771,") {
        return Err(format!(
            "JA3 must start with `771,` (got `{}…`)",
            &ja3[..ja3.len().min(12)]
        ));
    }
    if !ja4.starts_with("t13") {
        return Err(format!(
            "JA4 must start with `t13` (got `{}…`)",
            &ja4[..ja4.len().min(8)]
        ));
    }
    // Parse the Akamai H2 string for real (not a `split('|').count()` sniff): a
    // malformed SETTINGS/PRIORITY/pseudo-header section in a shipped or Tier-B
    // target fails closed here with the offending token, never a partial parse.
    if let Err(e) = crate::fingerprint::akamai_h2::AkamaiH2Fingerprint::parse(akamai_h2) {
        return Err(format!("Akamai-H2 invalid: {e}"));
    }
    if peet_h2.is_empty() {
        return Err("empty peetprint".to_string());
    }
    // peet.ws's `akamai_fingerprint_hash` IS md5(`akamai_fingerprint`). A stored
    // peet_h2 that is not md5(akamai_h2) lies about the H2 string it fingerprints
    //: fail closed with the real expected hash so the fix is one copy-paste.
    let expected = crate::fingerprint::ja3::md5_string(akamai_h2);
    if peet_h2 != expected {
        return Err(format!(
            "peet_h2 must be md5(akamai_h2); for {akamai_h2:?} that is {expected}, not {peet_h2}"
        ));
    }
    Ok(())
}

/// Check that a JA4's encoded cipher/extension **counts** agree with the
/// cipher/extension lists in the paired JA3 string. A canonical JA3 and a JA4
/// both exclude GREASE, so a JA4 `_a` section derived from the JA3 must report
/// exactly the JA3's cipher-list length and extension-list length.
///
/// A mismatch means the JA4 was **not** computed from the JA3, the two describe
/// different ClientHellos, so at least one is wrong. This is a pure internal
/// consistency check (no external reference needed); it cannot tell you which
/// side is correct, only that they disagree.
///
/// # Errors
/// `Err(reason)` when the JA3 is malformed, the JA4 is too short, or the counts
/// disagree.
pub fn ja4_counts_match_ja3(ja3: &str, ja4: &str) -> Result<(), String> {
    let fields: Vec<&str> = ja3.split(',').collect();
    if fields.len() != 5 {
        return Err(format!(
            "JA3 must have 5 comma-separated fields, got {}",
            fields.len()
        ));
    }
    let count = |field: &str| {
        if field.is_empty() {
            0
        } else {
            field.split('-').count()
        }
    };
    let ja3_ciphers = count(fields[1]);
    let ja3_exts = count(fields[2]);

    // JA4 `_a`: t{ver:2}{sni:1}{ciphers:2}{exts:2}{alpn:2}… (counts at [4..6] and [6..8]).
    if ja4.len() < 8 {
        return Err(format!("JA4 too short to carry counts: {ja4}"));
    }
    let ja4_ciphers: usize = ja4[4..6]
        .parse()
        .map_err(|_| format!("JA4 cipher-count digits not numeric: {ja4}"))?;
    let ja4_exts: usize = ja4[6..8]
        .parse()
        .map_err(|_| format!("JA4 extension-count digits not numeric: {ja4}"))?;

    if ja4_ciphers != ja3_ciphers {
        return Err(format!(
            "JA4 cipher count {ja4_ciphers} != JA3 cipher-list length {ja3_ciphers} ({ja4} vs {ja3})"
        ));
    }
    if ja4_exts != ja3_exts {
        return Err(format!(
            "JA4 extension count {ja4_exts} != JA3 extension-list length {ja3_exts} ({ja4} vs {ja3})"
        ));
    }
    Ok(())
}
