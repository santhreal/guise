//! Chrome TLS and HTTP/2 fingerprint snapshots for diagnostics.
//!
//! These entries are used to compare an observed browser transport against
//! bundled Chrome handshake shapes. The catalogue is passive data: it does not
//! open network connections or alter TLS handshakes.
//!
//! Role (G010): the **versioned Chrome diagnostic snapshot** catalogue, full
//! JA3 string + MD5 hash + H2 fingerprint per Chrome major/platform, for
//! comparing an *observed* Chrome transport. Sibling catalogues:
//! `tls_profiles` (the structured `ClientHelloFields`/`ImpersonateProfile`
//! source) and `tls_targets` (per-label JA3/JA4/Akamai targets). Each entry's
//! `ja3_hash` is the MD5 of its own `ja3` string, enforced by
//! `every_snapshot_ja3_hash_is_the_real_md5_of_its_ja3_string`.

use serde::{Deserialize, Serialize};

/// One captured Chrome TLS and HTTP/2 fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChromeFingerprint {
    /// Human-readable name, for example `"Chrome 134 / Linux"`.
    pub name: &'static str,
    /// Chrome major version.
    pub major_version: u32,
    /// Platform string used by diagnostics.
    pub platform: &'static str,
    /// JA3 string: TLS version, ciphers, extensions, groups, and EC point
    /// formats.
    pub ja3: &'static str,
    /// JA3 hash as a 32-character lowercase hex string.
    pub ja3_hash: &'static str,
    /// JA4 string.
    pub ja4: &'static str,
    /// HTTP/2 fingerprint in Akamai-style
    /// `settings|window_update|priority|headers` form.
    pub h2_fingerprint: &'static str,
}

/// Bundled Chrome TLS and HTTP/2 fingerprint snapshots.
///
/// Entries are ordered by diagnostic preference. The resolver returns an exact
/// major/platform match when present, then the highest bundled major on the
/// same platform, then the first entry as a final fallback.
pub const CHROME_FINGERPRINTS: &[ChromeFingerprint] = &[
    // Current stable, measured live 2026-06-12 by driving the host's stock
    // Chrome/146 to tls.peet.ws. Records the real evolution past the 134 snapshot:
    // ECH (0xfe0d/65037) is now sent, ALPS moved to its new codepoint 0x44cd
    // (17613, was 0x4469/17513), pre_shared_key (0x0029/41) is present, and the
    // supported-groups now lead with the post-quantum hybrid X25519MLKEM768
    // (0x11ec/4588), together moving the JA4 _c ext-hash to b6f405a00624 (the 134
    // snapshot's b0da82dd1658 predates ECH/ALPS-44cd). The JA4 is the AUTHORITATIVE,
    // cross-connection-STABLE fingerprint: Chrome shuffles its TLS extension order
    // per connection (RFC-8701), proven here by 3 captures that produced 3 distinct
    // JA3 hashes but ONE identical JA4. The `ja3` below is therefore a representative
    // SAMPLE order (self-consistent md5), NOT a fixed match key (match Chrome on JA4).
    ChromeFingerprint {
        name: "Chrome 146 / Linux",
        major_version: 146,
        platform: "Linux",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-45-18-27-10-35-16-43-65281-65037-11-23-51-13-17613-41,4588-29-23-24,0",
        ja3_hash: "1bd7f9ece339f0b2e6720b2c781823d6",
        ja4: "t13d1517h2_8daaf6152771_b6f405a00624",
        h2_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
    ChromeFingerprint {
        name: "Chrome 134 / Linux",
        major_version: 134,
        platform: "Linux",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658",
        h2_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
    ChromeFingerprint {
        name: "Chrome 133 / Linux",
        major_version: 133,
        platform: "Linux",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
        ja3_hash: "b32309a26951912be7dba376398abc3b",
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658",
        h2_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
    ChromeFingerprint {
        name: "Chrome 132 / Linux",
        major_version: 132,
        platform: "Linux",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
        ja3_hash: "b32309a26951912be7dba376398abc3b",
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658",
        h2_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
    ChromeFingerprint {
        name: "Chrome 131 / Linux",
        major_version: 131,
        platform: "Linux",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
        ja3_hash: "b32309a26951912be7dba376398abc3b",
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658",
        h2_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
    ChromeFingerprint {
        name: "Chrome 130 / Linux",
        major_version: 130,
        platform: "Linux",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
        ja3_hash: "b32309a26951912be7dba376398abc3b",
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658",
        h2_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
    ChromeFingerprint {
        name: "Chrome 134 / macOS",
        major_version: 134,
        platform: "macOS",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658",
        h2_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
    ChromeFingerprint {
        name: "Chrome 134 / Windows",
        major_version: 134,
        platform: "Windows",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        ja4: "t13d1517h2_8daaf6152771_b0da82dd1658",
        h2_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
    ChromeFingerprint {
        name: "Chrome 134 / Android",
        major_version: 134,
        platform: "Android",
        ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
        ja3_hash: "b32309a26951912be7dba376398abc3b",
        ja4: "t13d1516h2_8daaf6152771_b0da82dd1658",
        h2_fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    },
];

/// Return the expected Chrome fingerprint for `major` and `platform`.
///
/// Resolution prefers an exact match, then the highest bundled major for the
/// same platform, then the first bundled entry.
#[must_use]
pub fn expected_fingerprint(major: u32, platform: &str) -> Option<&'static ChromeFingerprint> {
    if let Some(fingerprint) = CHROME_FINGERPRINTS
        .iter()
        .find(|fingerprint| fingerprint.major_version == major && fingerprint.platform == platform)
    {
        return Some(fingerprint);
    }

    let mut latest: Option<&'static ChromeFingerprint> = None;
    for fingerprint in CHROME_FINGERPRINTS {
        if fingerprint.platform == platform
            && latest.map(|current| current.major_version).unwrap_or(0) <= fingerprint.major_version
        {
            latest = Some(fingerprint);
        }
    }
    latest.or_else(|| CHROME_FINGERPRINTS.first())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_covers_multiple_chrome_majors() {
        let mut majors: Vec<u32> = CHROME_FINGERPRINTS
            .iter()
            .map(|fingerprint| fingerprint.major_version)
            .collect();
        majors.sort_unstable();
        majors.dedup();
        assert!(
            majors.len() >= 5,
            "fingerprint table covers {} majors, expected >=5",
            majors.len()
        );
    }

    #[test]
    fn catalogue_covers_desktop_and_mobile_platforms() {
        let mut platforms: Vec<&str> = CHROME_FINGERPRINTS
            .iter()
            .map(|fingerprint| fingerprint.platform)
            .collect();
        platforms.sort_unstable();
        platforms.dedup();
        for platform in ["Linux", "macOS", "Windows", "Android"] {
            assert!(
                platforms.contains(&platform),
                "missing platform: {platform}"
            );
        }
    }

    #[test]
    fn ja3_hashes_are_md5_length() {
        for fingerprint in CHROME_FINGERPRINTS {
            assert_eq!(
                fingerprint.ja3_hash.len(),
                32,
                "{}: ja3_hash must be 32 chars",
                fingerprint.name
            );
        }
    }

    #[test]
    fn expected_fingerprint_finds_exact_match() {
        let fingerprint = expected_fingerprint(134, "Linux").expect("must find Chrome 134/Linux");
        assert_eq!(fingerprint.major_version, 134);
        assert_eq!(fingerprint.platform, "Linux");
    }

    #[test]
    fn expected_fingerprint_falls_back_to_highest_same_platform() {
        let fingerprint =
            expected_fingerprint(9999, "Linux").expect("must fall back to a Linux entry");
        assert_eq!(fingerprint.platform, "Linux");
        assert!(fingerprint.major_version >= 130);
    }

    #[test]
    fn expected_fingerprint_falls_back_to_first_entry_for_unknown_platform() {
        assert_eq!(
            expected_fingerprint(134, "FreeBSD"),
            CHROME_FINGERPRINTS.first()
        );
    }

    #[test]
    fn ja3_strings_have_five_segments() {
        for fingerprint in CHROME_FINGERPRINTS {
            let segments: Vec<&str> = fingerprint.ja3.split(',').collect();
            assert_eq!(
                segments.len(),
                5,
                "{} ja3 string has wrong segment count: {}",
                fingerprint.name,
                fingerprint.ja3
            );
        }
    }

    #[test]
    fn ja4_strings_are_tls13_grade() {
        for fingerprint in CHROME_FINGERPRINTS {
            assert!(
                fingerprint.ja4.starts_with("t13d"),
                "{} ja4 does not look like TLS 1.3: {}",
                fingerprint.name,
                fingerprint.ja4
            );
        }
    }

    #[test]
    fn h2_fingerprints_have_four_segments() {
        for fingerprint in CHROME_FINGERPRINTS {
            let segments: Vec<&str> = fingerprint.h2_fingerprint.split('|').collect();
            assert_eq!(
                segments.len(),
                4,
                "{} h2 fingerprint has wrong segment count: {}",
                fingerprint.name,
                fingerprint.h2_fingerprint
            );
        }
    }

    #[test]
    fn every_snapshot_ja3_hash_is_the_real_md5_of_its_ja3_string() {
        // Integrity guard: ja3_hash is the MD5 checksum of ja3, by definition. A
        // stored hash that is not md5(ja3) is fabricated/drifted data, exactly the
        // bug that shipped here (Chrome 130-133/Linux + 134/Android all carried the
        // Chrome-134/Linux hash despite different ja3 strings). This locks every
        // entry's checksum to its own string so the catalogue can never ship a
        // fingerprint whose hash lies about its bytes.
        for fingerprint in CHROME_FINGERPRINTS {
            let real = crate::fingerprint::ja3::md5_string(fingerprint.ja3);
            assert_eq!(
                fingerprint.ja3_hash, real,
                "{}: stored ja3_hash {} is not md5(ja3); real md5 is {}",
                fingerprint.name, fingerprint.ja3_hash, real
            );
        }
    }

    #[test]
    fn ja3_string_and_hash_are_distinct_across_extension_variants() {
        // The two distinct Chrome shapes (with vs without the 17513
        // application-settings extension) must hash to DIFFERENT values, proving
        // the integrity guard above actually discriminates and isn't trivially
        // satisfiable by a shared constant.
        let with_17513 = CHROME_FINGERPRINTS
            .iter()
            .find(|f| f.ja3.contains("-17513-"))
            .expect("a 17513-bearing Chrome snapshot ships");
        let without_17513 = CHROME_FINGERPRINTS
            .iter()
            .find(|f| !f.ja3.contains("-17513-"))
            .expect("a non-17513 Chrome snapshot ships");
        assert_ne!(with_17513.ja3, without_17513.ja3);
        assert_ne!(
            with_17513.ja3_hash, without_17513.ja3_hash,
            "different ja3 strings must not share a hash"
        );
    }
}
