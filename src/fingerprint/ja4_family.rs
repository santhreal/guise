//! The full JA4+ fingerprint family for captured network artifacts.
//!
//! FoxIO JA4+ extends the client-only JA3/JA4 concept to the server side,
//! light-distance, and certificate surfaces. This module provides pure,
//! allocation-light transforms over already-extracted handshake/certificate
//! fields (it does not parse packets or open sockets).
//!
//! Coverage (G002):
//! - [`compute_ja4s`]. TLS/QUIC `ServerHello` fingerprint.
//! - [`compute_ja4l`] (one-way latency + TTL fingerprint).
//! - [`compute_ja4x`]. X.509 certificate structural fingerprint.
//!
//! The client-side JA4 computation lives in [`super::ja3`] because that is
//! where the `ClientHelloFields` type already existed; this module owns the
//! *family* surface and any future client migration will converge here.

use crate::fingerprint::ja4_hash::sha256_first_12;

/// Transport protocol identifier used in the JA4 prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProto {
    /// TCP TLS.
    Tcp,
    /// QUIC TLS.
    Quic,
    /// DTLS.
    Dtls,
}

impl TransportProto {
    /// Single-character prefix used by FoxIO.
    #[must_use]
    pub const fn ja4_char(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Quic => 'q',
            Self::Dtls => 'd',
        }
    }
}

/// GREASE values (RFC 8701) that must be ignored when deriving the effective
/// TLS version from a `supported_versions` extension.
const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn is_grease(value: u16) -> bool {
    GREASE_VALUES.contains(&value)
}

fn tls_version_char(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0200 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn effective_tls_version(legacy: u16, supported_versions: &[u16]) -> u16 {
    supported_versions
        .iter()
        .copied()
        .find(|version| !is_grease(*version))
        .unwrap_or(legacy)
}

fn alpn_part(alpn: &[String]) -> String {
    match alpn.first() {
        Some(value) if !value.is_empty() => {
            let bytes = value.as_bytes();
            let safe = |byte: u8| -> char {
                let candidate = byte as char;
                if candidate.is_ascii_alphanumeric() {
                    candidate
                } else {
                    '0'
                }
            };
            format!(
                "{}{}",
                safe(*bytes.first().unwrap_or(&0)),
                safe(*bytes.last().unwrap_or(&0))
            )
        }
        _ => "00".to_string(),
    }
}

/// Fields extracted from a TLS `ServerHello` used by JA4S.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloFields {
    /// Legacy protocol version encoded in the ServerHello.
    pub version: u16,
    /// Contents of the `supported_versions` extension (0x002b), if present.
    /// JA4S derives its version digit from the first non-GREASE entry.
    pub supported_versions: Vec<u16>,
    /// Selected cipher suite.
    pub cipher: u16,
    /// Extension type ids offered in the ServerHello, in wire order.
    pub extensions: Vec<u16>,
    /// Negotiated ALPN protocol, if any.
    pub alpn: Vec<String>,
    /// Transport protocol (TCP/QUIC/DTLS) for the prefix character.
    pub proto: TransportProto,
}

impl ServerHelloFields {
    /// The effective TLS version used by JA4S: the first non-GREASE entry of
    /// `supported_versions` when present, otherwise the legacy field.
    #[must_use]
    pub fn effective_tls_version(&self) -> u16 {
        effective_tls_version(self.version, &self.supported_versions)
    }
}

/// Compute the FoxIO JA4S fingerprint for a captured `ServerHello`.
///
/// Format: `<proto><ver><ext_count><alpn>_<cipher>_<ext_hash>`.
/// Extensions are sorted numerically before hashing, matching the FoxIO
/// reference behavior.
#[must_use]
pub fn compute_ja4s(fields: &ServerHelloFields) -> String {
    let version = tls_version_char(fields.effective_tls_version());
    let ext_count = format!("{:02}", fields.extensions.len().min(99));
    let alpn = alpn_part(&fields.alpn);
    let part_a = format!(
        "{}{}{}{}",
        fields.proto.ja4_char(),
        version,
        ext_count,
        alpn
    );

    let cipher = format!("{:04x}", fields.cipher);

    let ext_hash = if fields.extensions.is_empty() {
        "000000000000".to_string()
    } else {
        let mut sorted = fields.extensions.clone();
        sorted.sort_unstable();
        let input = sorted
            .iter()
            .map(|extension| format!("{extension:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        sha256_first_12(&input)
    };

    format!("{part_a}_{cipher}_{ext_hash}")
}

/// Which side of a connection produced a JA4L latency sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencySide {
    /// Client-measured (the final ACK of a TCP three-way handshake).
    Client,
    /// Server-measured (the SYN-ACK).
    Server,
}

impl LatencySide {
    #[must_use]
    fn ja4_char(self) -> char {
        match self {
            Self::Client => 'C',
            Self::Server => 'S',
        }
    }
}

/// One JA4L light-distance sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencySample {
    /// Which side produced the sample.
    pub side: LatencySide,
    /// One-way latency in microseconds (must be >= 1).
    pub latency_us: u64,
    /// IP TTL observed on the packet that produced the sample.
    pub ttl: u8,
}

/// Compute the FoxIO JA4L latency fingerprint.
///
/// Format: `JA4L-<side>=<latency_us>_<ttl>`.
#[must_use]
pub fn compute_ja4l(sample: &LatencySample) -> String {
    format!(
        "JA4L-{}={}_{}",
        sample.side.ja4_char(),
        sample.latency_us,
        sample.ttl
    )
}

/// Estimate physical distance from one-way latency.
///
/// Uses the FoxIO rule-of-thumb: speed of light in fiber ≈ 0.128 miles per
/// microsecond, divided by a propagation factor (default 1.6) that accounts
/// for fiber routes and electronics.
#[must_use]
pub fn light_distance_miles(latency_us: u64, propagation_factor: f64) -> f64 {
    const SPEED_OF_LIGHT_MILES_PER_US: f64 = 0.128;
    (latency_us as f64 * SPEED_OF_LIGHT_MILES_PER_US) / propagation_factor
}

/// Estimate physical distance in kilometers from one-way latency.
#[must_use]
pub fn light_distance_km(latency_us: u64, propagation_factor: f64) -> f64 {
    const SPEED_OF_LIGHT_KM_PER_US: f64 = 0.206;
    (latency_us as f64 * SPEED_OF_LIGHT_KM_PER_US) / propagation_factor
}

/// Which side of a TCP three-way handshake produced a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpHandshakeRole {
    /// Client SYN.
    Syn,
    /// Server SYN-ACK.
    SynAck,
    /// Client ACK.
    Ack,
}

/// Compute a JA4L fingerprint from TCP three-way handshake timestamps.
///
/// Returns `None` when the provided packet is not the right role for a sample
/// (e.g. a SYN does not yet have a latency value).
#[must_use]
pub fn compute_ja4l_from_tcp_handshake(
    role: TcpHandshakeRole,
    latency_us: u64,
    ttl: u8,
) -> Option<String> {
    let sample = match role {
        TcpHandshakeRole::Syn => return None,
        TcpHandshakeRole::SynAck => LatencySample {
            side: LatencySide::Server,
            latency_us: latency_us.max(1),
            ttl,
        },
        TcpHandshakeRole::Ack => LatencySample {
            side: LatencySide::Client,
            latency_us: latency_us.max(1),
            ttl,
        },
    };
    Some(compute_ja4l(&sample))
}

/// Parse error returned when an OID string is not valid dotted-decimal form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidParseError {
    oid: String,
}

impl std::fmt::Display for OidParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid OID dotted string: {}", self.oid)
    }
}

impl std::error::Error for OidParseError {}

/// ASN.1 DER-encode an OID dotted string to lowercase hex.
///
/// The first two components are combined (`first * 40 + second`) and remaining
/// components use variable-length quantity (VLQ) encoding for values ≥ 128.
/// This matches the FoxIO reference behavior used by JA4X.
///
/// # Examples
///
/// ```
/// use guise::fingerprint::ja4_family::oid_to_hex;
///
/// assert_eq!(oid_to_hex("2.5.4.3").unwrap(), "550403");
/// assert_eq!(oid_to_hex("2.5.29.17").unwrap(), "551d11");
/// ```
pub fn oid_to_hex(oid: &str) -> Result<String, OidParseError> {
    let parts: Vec<u32> = oid
        .split('.')
        .map(|part| {
            part.parse::<u32>().map_err(|_| OidParseError {
                oid: oid.to_string(),
            })
        })
        .collect::<Result<_, _>>()?;

    if parts.len() < 2 {
        return Err(OidParseError {
            oid: oid.to_string(),
        });
    }

    let mut bytes: Vec<u32> = Vec::with_capacity(parts.len());
    bytes.push(parts[0] * 40 + parts[1]);

    for &part in &parts[2..] {
        if part < 0x80 {
            bytes.push(part);
        } else {
            let mut value = part;
            let mut vlq = Vec::new();
            vlq.push(value & 0x7f);
            value >>= 7;
            while value > 0 {
                vlq.push((value & 0x7f) | 0x80);
                value >>= 7;
            }
            vlq.reverse();
            bytes.extend(vlq);
        }
    }

    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// X.509 certificate fields used by JA4X.
///
/// Each vector contains the hex-encoded OIDs of the relative distinguished
/// names (issuer/subject) and extension OIDs, in certificate order. Callers
/// that already have an X.509 parser supply these directly; the helper
/// [`oid_to_hex`] converts dotted OID strings to the required hex form.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertificateFields {
    /// Hex-encoded issuer RDN OIDs, in order.
    pub issuer_rdns: Vec<String>,
    /// Hex-encoded subject RDN OIDs, in order.
    pub subject_rdns: Vec<String>,
    /// Hex-encoded extension OIDs, in order.
    pub extensions: Vec<String>,
}

fn hash_rdn_list(values: &[String]) -> String {
    if values.is_empty() {
        return "000000000000".to_string();
    }
    sha256_first_12(&values.join(","))
}

/// Compute the FoxIO JA4X certificate fingerprint.
///
/// Format: `<issuer_hash>_<subject_hash>_<extensions_hash>` where each hash
/// is the SHA-256 of the comma-joined, hex-encoded OID list, truncated to
/// twelve hex chars. Empty lists produce the sentinel `000000000000`.
#[must_use]
pub fn compute_ja4x(fields: &CertificateFields) -> String {
    format!(
        "{}_{}_{}",
        hash_rdn_list(&fields.issuer_rdns),
        hash_rdn_list(&fields.subject_rdns),
        hash_rdn_list(&fields.extensions)
    )
}

#[cfg(test)]
#[path = "ja4_family/tests.rs"]
mod tests;
