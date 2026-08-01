//! JA3 and JA4 fingerprint computation for captured TLS ClientHello fields.
//!
//! The functions here are pure transforms over already-extracted handshake
//! fields. They do not open sockets, parse packets, or emit TLS handshakes.

mod hash;

pub(crate) use hash::{md5_string, sha256_first_12};

/// One TLS ClientHello, broken into the fields used by JA3 and JA4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloFields {
    /// TLS legacy protocol version encoded in the ClientHello.
    pub version: u16,
    /// Cipher suites offered by the client, in client-preferred order.
    pub cipher_suites: Vec<u16>,
    /// Extension type ids offered by the client, in wire order.
    pub extensions: Vec<u16>,
    /// Supported elliptic-curve groups.
    pub supported_groups: Vec<u16>,
    /// EC point formats.
    pub ec_point_formats: Vec<u8>,
    /// ALPN protocols, in client-preferred order (raw bytes).
    pub alpn: Vec<Vec<u8>>,
    /// Signature algorithm ids, in client-offered order.
    pub signature_algorithms: Vec<u16>,
    /// TLS versions offered in the `supported_versions` extension (0x002b), if
    /// the client sends it. JA4 derives its version digit from the HIGHEST entry
    /// here (GREASE-stripped), falling back to the legacy [`Self::version`] field
    /// only when this is empty, so a modern browser whose legacy version is
    /// pinned to TLS 1.2 (0x0303) for middlebox compat is still fingerprinted as
    /// the TLS 1.3 client it is.
    pub supported_versions: Vec<u16>,
}

impl ClientHelloFields {
    /// Return a copy of this ClientHello shape with `alpn` populated.
    #[must_use]
    pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }

    /// Return a copy of this ClientHello shape with `algs` populated.
    #[must_use]
    pub fn with_signature_algorithms(mut self, algs: Vec<u16>) -> Self {
        self.signature_algorithms = algs;
        self
    }

    /// Return a copy of this ClientHello shape with `versions` (the
    /// `supported_versions` extension contents) populated.
    #[must_use]
    pub fn with_supported_versions(mut self, versions: Vec<u16>) -> Self {
        self.supported_versions = versions;
        self
    }

    /// The highest TLS version this client actually negotiates: the max
    /// GREASE-stripped entry of [`Self::supported_versions`] when present,
    /// otherwise the legacy [`Self::version`] field. This is the value JA4
    /// encodes (not the spoofable legacy field a TLS 1.3 client pins to 0x0303).
    #[must_use]
    pub fn effective_tls_version(&self) -> u16 {
        self.supported_versions
            .iter()
            .copied()
            .filter(|version| !is_grease(*version))
            .max()
            .unwrap_or(self.version)
    }
}

const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Compute the canonical JA3 string from ClientHello fields.
///
/// JA3 uses `version,cipher_suites,extensions,supported_groups,ec_point_formats`
/// with dash-joined numeric lists. GREASE values are stripped from all `u16`
/// lists before rendering.
#[must_use]
pub fn compute_ja3(fields: &ClientHelloFields) -> String {
    let cipher = join_u16_dash(&fields.cipher_suites);
    let ext = join_u16_dash(&fields.extensions);
    let groups = join_u16_dash(&fields.supported_groups);
    let formats = join_u8_dash(&fields.ec_point_formats);
    format!(
        "{},{},{},{},{}",
        fields.version, cipher, ext, groups, formats
    )
}

/// Compute the MD5 hash of the canonical JA3 string.
#[must_use]
pub fn compute_ja3_hash(fields: &ClientHelloFields) -> String {
    let canonical = compute_ja3(fields);
    md5_string(&canonical)
}

/// Compute a JA4 string for a TCP TLS ClientHello.
///
/// The implementation follows FoxIO JA4 shape:
/// `<proto><ver><sni><nciphers><nexts><alpn>_<cipherhash12>_<exthash12>`.
/// Cipher and extension hash inputs are GREASE-stripped, hex-rendered, and
/// sorted as required by the JA4 spec. Signature algorithms are appended to the
/// extension hash input in client-offered order.
#[must_use]
pub fn compute_ja4(fields: &ClientHelloFields) -> String {
    // JA4 takes the highest NEGOTIATED version (from the supported_versions
    // extension), not the legacy ClientHello version a TLS 1.3 client pins to
    // 0x0303. `effective_tls_version` resolves that, with the legacy field as the
    // spec-defined fallback when no supported_versions extension is sent.
    let tls_version = match fields.effective_tls_version() {
        769 => "10",
        770 => "11",
        771 => "12",
        772 => "13",
        _ => "00",
    };

    let alpn_field = match fields.alpn.first() {
        Some(value) if !value.is_empty() => {
            let safe = |byte: u8| -> char {
                let candidate = byte as char;
                if candidate.is_ascii_alphanumeric() {
                    candidate
                } else {
                    '0'
                }
            };
            let first = safe(value.first().copied().unwrap_or(b'0'));
            let last = safe(value.last().copied().unwrap_or(b'0'));
            format!("{first}{last}")
        }
        _ => "00".to_string(),
    };

    let cipher_filtered: Vec<u16> = fields
        .cipher_suites
        .iter()
        .copied()
        .filter(|cipher| !is_grease(*cipher))
        .collect();
    // JA4 _a extension COUNT includes ALL non-GREASE extensions. SNI (0x0000)
    // and ALPN (0x0010) ARE counted here (FoxIO spec). They are removed ONLY from
    // the sorted _c hash below. Counting the post-exclusion list understated the
    // count by the SNI/ALPN present (≈2), yielding e.g. `t13d1715h2` where a real
    // Firefox-150 emits `t13d1717h2`: a JA4 that diverges from the canonical
    // value real browsers and JA4 databases produce, i.e. a fingerprint tell.
    let ext_nongrease_count = fields
        .extensions
        .iter()
        .filter(|extension| !is_grease(**extension))
        .count();
    let ext_filtered: Vec<u16> = fields
        .extensions
        .iter()
        .copied()
        .filter(|extension| !is_grease(*extension))
        .filter(|extension| *extension != 0x0000 && *extension != 0x0010)
        .collect();
    let cipher_count = format!("{:02}", cipher_filtered.len().min(99));
    let ext_count = format!("{:02}", ext_nongrease_count.min(99));

    let mut sorted_ciphers = cipher_filtered.clone();
    sorted_ciphers.sort_unstable();
    let cipher_hash_input = sorted_ciphers
        .iter()
        .map(|cipher| format!("{cipher:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let cipher_hash = sha256_first_12(&cipher_hash_input);

    let mut sorted_exts = ext_filtered.clone();
    sorted_exts.sort_unstable();
    let ext_hex = sorted_exts
        .iter()
        .map(|extension| format!("{extension:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let sigalg_hex = fields
        .signature_algorithms
        .iter()
        .map(|algorithm| format!("{algorithm:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let ext_hash_input = if sigalg_hex.is_empty() {
        ext_hex
    } else {
        format!("{ext_hex}_{sigalg_hex}")
    };
    let ext_hash = sha256_first_12(&ext_hash_input);

    // JA4 SNI indicator: `d` when the ClientHello carries a server_name (SNI)
    // extension (0x0000), `i` otherwise (IP / no SNI). Derived from the extension
    // list, not hardcoded, a hardcoded `d` mislabels a no-SNI handshake as
    // domain-routed. Browser traffic always sends SNI, so this stays `d` for every
    // real-browser persona; the derivation only corrects the no-SNI case.
    let sni = if fields.extensions.contains(&0x0000) {
        "d"
    } else {
        "i"
    };

    format!("t{tls_version}{sni}{cipher_count}{ext_count}{alpn_field}_{cipher_hash}_{ext_hash}")
}

/// Verify a captured ClientHello against a target JA3 string.
#[must_use]
pub fn verify_against_target(
    actual: &ClientHelloFields,
    target_ja3: &str,
) -> JA3VerificationOutcome {
    let actual_ja3 = compute_ja3(actual);
    if actual_ja3 == target_ja3 {
        JA3VerificationOutcome::Match {
            canonical: actual_ja3,
        }
    } else {
        JA3VerificationOutcome::Drift {
            actual: actual_ja3,
            expected: target_ja3.to_string(),
        }
    }
}

/// Result of comparing an actual ClientHello against a target JA3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JA3VerificationOutcome {
    /// The actual ClientHello rendered to the expected canonical JA3 string.
    Match {
        /// Actual canonical JA3 string.
        canonical: String,
    },
    /// The actual ClientHello rendered to a different canonical JA3 string.
    Drift {
        /// Actual canonical JA3 string.
        actual: String,
        /// Expected canonical JA3 string.
        expected: String,
    },
}

impl JA3VerificationOutcome {
    /// Return true when this comparison is a match.
    #[must_use]
    pub fn is_match(&self) -> bool {
        matches!(self, JA3VerificationOutcome::Match { .. })
    }
}

fn join_u16_dash(values: &[u16]) -> String {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn join_u8_dash(values: &[u8]) -> String {
    values
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn is_grease(value: u16) -> bool {
    GREASE_VALUES.contains(&value)
}

#[cfg(test)]
#[path = "ja3/tests.rs"]
mod tests;
