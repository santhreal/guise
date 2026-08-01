//! Browser-exact HTTP/2 client-opening EMITTER, the producer side of the X049
//! wire self-probe (`session_coherence::wire_probe`), which until now could only
//! *verify* a [`WireCapture`] supplied from outside (`tls.peet.ws`, a WAF) and had
//! no in-tree producer.
//!
//! A persona's HTTP/2 identity (the Akamai fingerprint
//! `SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header-order`) is determined by the
//! BYTES the client puts on the wire when it opens a connection: the SETTINGS
//! frame (entries in a browser-specific ORDER), the connection-level
//! WINDOW_UPDATE, any PRIORITY frames, and the pseudo-header order in the first
//! HEADERS frame. A general HTTP/2 stack (`h2`/`hyper`/`reqwest`) emits a FIXED
//! shape and cannot reorder SETTINGS or pseudo-headers, so it can never match
//! Firefox's `m,p,a,s` over `1:65536;2:0;4:131072;5:16384`. This module serializes
//! a [`H2Profile`] to the exact frames a browser of that family sends, and an
//! independent parser reads those frames back and reconstructs the canonical
//! Akamai string, so the emit is provable end-to-end (encode → real socket →
//! parse → `persona_wire_self_probe` ⇒ `Coherent`).
//!
//! Scope: this is the HTTP/2 FRAME layer. A fully browser-exact CONNECTION also
//! needs the matching TLS ClientHello (JA3/JA4), which is the `tls-impersonate`
//! BoringSSL path (`StealthClient`); this module does not speak TLS and makes no
//! claim about the TLS layer.

use crate::fingerprint::akamai_h2::{
    AkamaiH2Fingerprint, AkamaiH2ParseError, H2Priority, H2Setting, PseudoHeader,
};
use crate::http::session_coherence::H2Profile;

/// The HTTP/2 connection preface every client sends first (RFC 9113 §3.4).
pub const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame type codes (RFC 9113 §6).
const FRAME_HEADERS: u8 = 0x1;
const FRAME_PRIORITY: u8 = 0x2;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
// HEADERS flags.
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
// SETTINGS flags.
const FLAG_ACK: u8 = 0x1;

/// A model that cannot be serialized, the persona's rendered Akamai string did
/// not parse. Surfaced loudly rather than emitting a guessed/partial opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireEmitError {
    /// The profile's own `akamai_fingerprint()` failed the canonical parser.
    Model(AkamaiH2ParseError),
}

impl core::fmt::Display for WireEmitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Model(e) => write!(f, "persona Akamai model does not parse: {e:?}"),
        }
    }
}
impl std::error::Error for WireEmitError {}

/// A wire-parse failure. Every variant fails CLOSED, a truncated or malformed
/// opening is NEVER reconstructed into a partial/empty Akamai string that could
/// read as agreement in the self-probe (Law: no silent fallback).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireParseError {
    /// The leading bytes were not the HTTP/2 client preface.
    BadPreface,
    /// A frame header or payload ran past the end of the buffer.
    Truncated,
    /// A SETTINGS frame payload was not a multiple of 6 bytes.
    BadSettings,
    /// A PRIORITY frame payload was not exactly 5 bytes.
    BadPriority,
    /// An HPACK representation this oracle does not implement (e.g. a
    /// Huffman-coded header NAME) (refused rather than silently mis-decoded).
    UnsupportedHpack,
    /// The opening ended before any HEADERS frame, so no pseudo-header order was
    /// observed (there is nothing to compare; never treated as a match).
    NoHeaders,
}

impl core::fmt::Display for WireParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::BadPreface => "not an HTTP/2 client preface",
            Self::Truncated => "frame ran past end of buffer (truncated)",
            Self::BadSettings => "SETTINGS payload not a multiple of 6 bytes",
            Self::BadPriority => "PRIORITY payload not 5 bytes",
            Self::UnsupportedHpack => "unsupported HPACK representation in HEADERS",
            Self::NoHeaders => "opening ended before any HEADERS frame",
        };
        f.write_str(s)
    }
}
impl std::error::Error for WireParseError {}

/// Serialize the client-side opening a browser of `profile`'s family emits:
/// preface, SETTINGS (entries in profile order), the connection WINDOW_UPDATE
/// (omitted when the profile's increment is `0`), any PRIORITY frames, then the
/// first request's HEADERS with pseudo-headers in profile order. `authority`/
/// `path` populate `:authority`/`:path` for the request line.
///
/// # Errors
/// [`WireEmitError::Model`] if the profile's own Akamai rendering does not parse
/// (a corrupt profile) (emission fails loud, never producing a guessed opening).
pub fn encode_client_opening_for_profile(
    profile: &H2Profile,
    authority: &str,
    path: &str,
) -> Result<Vec<u8>, WireEmitError> {
    // Drive the emitter from the canonical structured form (reuses the one Akamai
    // parser (no second priority/settings string parser here)).
    let fp =
        AkamaiH2Fingerprint::parse(&profile.akamai_fingerprint()).map_err(WireEmitError::Model)?;
    Ok(encode_client_opening(&fp, authority, path))
}

/// Serialize a client opening directly from a structured [`AkamaiH2Fingerprint`].
/// Round-trips [`parse_client_akamai`]: `parse(encode(fp)) == fp.to_canonical()`.
#[must_use]
pub fn encode_client_opening(fp: &AkamaiH2Fingerprint, authority: &str, path: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(H2_CLIENT_PREFACE);

    // SETTINGS frame (entries in the exact model order (6 bytes each)).
    let mut settings = Vec::with_capacity(fp.settings.len() * 6);
    for s in &fp.settings {
        settings.extend_from_slice(&s.id.to_be_bytes());
        settings.extend_from_slice(&s.value.to_be_bytes());
    }
    push_frame(&mut out, FRAME_SETTINGS, 0, 0, &settings);

    // Connection-level WINDOW_UPDATE (only when one is actually sent).
    if fp.window_update != 0 {
        push_frame(
            &mut out,
            FRAME_WINDOW_UPDATE,
            0,
            0,
            &fp.window_update.to_be_bytes(),
        );
    }

    // PRIORITY frames (modern Chrome/Firefox/Safari send none → empty).
    for p in &fp.priorities {
        let mut payload = Vec::with_capacity(5);
        let dep = (p.dependent & 0x7fff_ffff) | ((u32::from(p.exclusive) & 1) << 31);
        payload.extend_from_slice(&dep.to_be_bytes());
        // The model carries weight as the wire value; emit it as the weight byte.
        payload.push(p.weight as u8);
        push_frame(&mut out, FRAME_PRIORITY, 0, p.stream_id, &payload);
    }

    // HEADERS frame on stream 1, pseudo-headers in model order.
    let mut block = Vec::with_capacity(32);
    for ph in &fp.pseudo_header_order {
        push_pseudo_header(&mut block, *ph, authority, path);
    }
    push_frame(
        &mut out,
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &block,
    );
    out
}

/// Parse a captured client opening back into the canonical Akamai string
/// (`SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header-order`), an INDEPENDENT
/// reader (not the encoder run backwards) so a round-trip proves the bytes, not
/// just the code. Reconstruction goes through the canonical
/// [`AkamaiH2Fingerprint::to_canonical`] so the format always matches the model.
///
/// # Errors
/// A [`WireParseError`] on any malformed/truncated/unsupported input, fails
/// closed, never a partial string.
pub fn parse_client_akamai(bytes: &[u8]) -> Result<String, WireParseError> {
    if bytes.len() < H2_CLIENT_PREFACE.len()
        || &bytes[..H2_CLIENT_PREFACE.len()] != H2_CLIENT_PREFACE
    {
        return Err(WireParseError::BadPreface);
    }
    let mut pos = H2_CLIENT_PREFACE.len();

    let mut settings: Vec<H2Setting> = Vec::new();
    let mut window_update: u32 = 0;
    let mut priorities: Vec<H2Priority> = Vec::new();
    let mut pseudo_header_order: Option<Vec<PseudoHeader>> = None;

    while pos + 9 <= bytes.len() {
        let len = (usize::from(bytes[pos]) << 16)
            | (usize::from(bytes[pos + 1]) << 8)
            | usize::from(bytes[pos + 2]);
        let ftype = bytes[pos + 3];
        let flags = bytes[pos + 4];
        let stream = u32::from_be_bytes([
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
            bytes[pos + 8],
        ]) & 0x7fff_ffff;
        let body_start = pos + 9;
        let body_end = body_start
            .checked_add(len)
            .ok_or(WireParseError::Truncated)?;
        if body_end > bytes.len() {
            return Err(WireParseError::Truncated);
        }
        let payload = &bytes[body_start..body_end];

        match ftype {
            FRAME_SETTINGS if flags & FLAG_ACK == 0 => {
                if !payload.len().is_multiple_of(6) {
                    return Err(WireParseError::BadSettings);
                }
                for chunk in payload.chunks_exact(6) {
                    let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                    let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                    settings.push(H2Setting { id, value });
                }
            }
            FRAME_WINDOW_UPDATE if stream == 0 => {
                if payload.len() != 4 {
                    return Err(WireParseError::Truncated);
                }
                // The connection-level increment is the Akamai field; record the
                // first one (browsers send exactly one on open).
                if window_update == 0 {
                    window_update =
                        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                            & 0x7fff_ffff;
                }
            }
            FRAME_PRIORITY => {
                if payload.len() != 5 {
                    return Err(WireParseError::BadPriority);
                }
                let raw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                priorities.push(H2Priority {
                    stream_id: stream,
                    exclusive: u8::from(raw & 0x8000_0000 != 0),
                    dependent: raw & 0x7fff_ffff,
                    weight: u16::from(payload[4]),
                });
            }
            FRAME_HEADERS => {
                pseudo_header_order = Some(decode_pseudo_header_order(payload)?);
                break; // request started; the opening's Akamai is fully observed.
            }
            // Any other frame (PING, etc.) is irrelevant to the Akamai shape; per
            // RFC 9113 unknown/irrelevant frames are skipped. This is correct H2
            // parsing, not a degraded fallback (the Akamai fields are unaffected).
            _ => {}
        }
        pos = body_end;
    }

    let Some(pseudo_header_order) = pseudo_header_order else {
        return Err(WireParseError::NoHeaders);
    };

    Ok(AkamaiH2Fingerprint {
        settings,
        window_update,
        priorities,
        pseudo_header_order,
    }
    .to_canonical())
}

/// Parse a captured opening into a [`WireCapture`](crate::http::session_coherence::WireCapture)
/// carrying only the observed Akamai fingerprint, ready to feed
/// [`persona_wire_self_probe`](crate::http::session_coherence::persona_wire_self_probe).
///
/// # Errors
/// Propagates [`parse_client_akamai`]'s [`WireParseError`].
pub fn capture_client_opening(
    bytes: &[u8],
) -> Result<crate::http::session_coherence::WireCapture, WireParseError> {
    Ok(crate::http::session_coherence::WireCapture {
        akamai_fingerprint: Some(parse_client_akamai(bytes)?),
        ..Default::default()
    })
}

// ── encoding helpers ───────────────────────────────────────────────────────

fn push_frame(out: &mut Vec<u8>, ftype: u8, flags: u8, stream: u32, payload: &[u8]) {
    let len = payload.len();
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(ftype);
    out.push(flags);
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Emit one pseudo-header into an HPACK block, browser-faithfully: a fully
/// indexed static entry for the common request line (`:method GET`, `:scheme
/// https`, `:path /`) and a static-name literal for `:authority` and non-root
/// paths. The Akamai pseudo-header-ORDER segment is the order these appear, which
/// is what this preserves.
fn push_pseudo_header(block: &mut Vec<u8>, ph: PseudoHeader, authority: &str, path: &str) {
    match ph {
        // Indexed Header Field (static table index (RFC 7541 §6.1): high bit set).
        PseudoHeader::Method => block.push(0x80 | 2), // :method GET
        PseudoHeader::Scheme => block.push(0x80 | 7), // :scheme https
        PseudoHeader::Path => {
            if path == "/" {
                block.push(0x80 | 4); // :path /
            } else {
                // Literal w/o Indexing, static name index 4 (:path): 0000_0100.
                block.push(0x04);
                push_hpack_string(block, path.as_bytes());
            }
        }
        PseudoHeader::Authority => {
            // Literal w/ Incremental Indexing, static name index 1 (:authority):
            // 01 + 6-bit index = 0x41 (RFC 7541 §6.2.1).
            block.push(0x41);
            push_hpack_string(block, authority.as_bytes());
        }
    }
}

/// HPACK string literal, no Huffman: `H=0` length (7-bit-prefix integer) + bytes.
fn push_hpack_string(out: &mut Vec<u8>, s: &[u8]) {
    push_hpack_int(out, s.len(), 7, 0x00);
    out.extend_from_slice(s);
}

/// HPACK integer (RFC 7541 §5.1) with `prefix_bits` and `first_byte_flags` OR-ed
/// into the leading byte's high bits.
fn push_hpack_int(out: &mut Vec<u8>, value: usize, prefix_bits: u32, first_byte_flags: u8) {
    let mask = (1usize << prefix_bits) - 1;
    if value < mask {
        out.push(first_byte_flags | value as u8);
        return;
    }
    out.push(first_byte_flags | mask as u8);
    let mut rem = value - mask;
    loop {
        let mut byte = (rem & 0x7f) as u8;
        rem >>= 7;
        if rem > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if rem == 0 {
            break;
        }
    }
}

// ── HPACK decode (only the subset this emitter produces; fails closed else) ──

/// Walk an HPACK header block recording the pseudo-header NAMES in wire order.
/// Handles the representations this module emits plus their literal forms; a
/// representation it does not model (e.g. a Huffman-coded NAME) is refused.
fn decode_pseudo_header_order(block: &[u8]) -> Result<Vec<PseudoHeader>, WireParseError> {
    let mut order = Vec::new();
    let mut i = 0usize;
    while i < block.len() {
        let b = block[i];
        let name = if b & 0x80 != 0 {
            // Indexed Header Field (static table entry, no value bytes).
            let idx = read_hpack_int(block, &mut i, 7)?;
            static_index_name(idx)
        } else if b & 0xc0 == 0x40 {
            // Literal w/ Incremental Indexing.
            let idx = read_hpack_int(block, &mut i, 6)?;
            let name = literal_name(block, &mut i, idx)?;
            skip_hpack_string(block, &mut i)?; // value
            name
        } else if b & 0xe0 == 0x20 {
            // Dynamic Table Size Update (no header; skip).
            read_hpack_int(block, &mut i, 5)?;
            None
        } else {
            // Literal w/o Indexing (0x00) or Never Indexed (0x10): 4-bit index.
            let idx = read_hpack_int(block, &mut i, 4)?;
            let name = literal_name(block, &mut i, idx)?;
            skip_hpack_string(block, &mut i)?; // value
            name
        };
        if let Some(ps) = name.and_then(pseudo_from_name) {
            order.push(ps);
        }
    }
    Ok(order)
}

/// Resolve a literal representation's header NAME: index 0 ⇒ a literal name
/// string (decoded here), otherwise the static-table name at `idx`.
fn literal_name(block: &[u8], i: &mut usize, idx: usize) -> Result<Option<String>, WireParseError> {
    if idx == 0 {
        return read_hpack_string(block, i);
    }
    Ok(static_index_name(idx))
}

/// The HTTP/2 HPACK static-table NAME for the pseudo-header indices this module
/// uses (RFC 7541 Appendix A). Non-pseudo / out-of-subset indices map to a
/// regular header name we don't track, returned as `None`.
fn static_index_name(idx: usize) -> Option<String> {
    match idx {
        1 => Some(":authority".into()),
        2 | 3 => Some(":method".into()),
        4 | 5 => Some(":path".into()),
        6 | 7 => Some(":scheme".into()),
        _ => None,
    }
}

fn pseudo_from_name(name: String) -> Option<PseudoHeader> {
    match name.as_str() {
        ":method" => Some(PseudoHeader::Method),
        ":path" => Some(PseudoHeader::Path),
        ":authority" => Some(PseudoHeader::Authority),
        ":scheme" => Some(PseudoHeader::Scheme),
        _ => None,
    }
}

/// Read (and UTF-8 decode) an HPACK string literal; Huffman is refused.
fn read_hpack_string(block: &[u8], i: &mut usize) -> Result<Option<String>, WireParseError> {
    if *i >= block.len() {
        return Err(WireParseError::Truncated);
    }
    let huffman = block[*i] & 0x80 != 0;
    let len = read_hpack_int(block, i, 7)?;
    let end = i.checked_add(len).ok_or(WireParseError::Truncated)?;
    if end > block.len() {
        return Err(WireParseError::Truncated);
    }
    if huffman {
        return Err(WireParseError::UnsupportedHpack);
    }
    let s = core::str::from_utf8(&block[*i..end])
        .map_err(|_| WireParseError::UnsupportedHpack)?
        .to_string();
    *i = end;
    Ok(Some(s))
}

/// Advance past an HPACK string literal (used for values we don't need); Huffman
/// values are skipped by length (we never decode them).
fn skip_hpack_string(block: &[u8], i: &mut usize) -> Result<(), WireParseError> {
    if *i >= block.len() {
        return Err(WireParseError::Truncated);
    }
    let len = read_hpack_int(block, i, 7)?;
    let end = i.checked_add(len).ok_or(WireParseError::Truncated)?;
    if end > block.len() {
        return Err(WireParseError::Truncated);
    }
    *i = end;
    Ok(())
}

/// Decode an HPACK integer with `prefix_bits` starting at `block[*i]`.
fn read_hpack_int(block: &[u8], i: &mut usize, prefix_bits: u32) -> Result<usize, WireParseError> {
    if *i >= block.len() {
        return Err(WireParseError::Truncated);
    }
    let mask = (1usize << prefix_bits) - 1;
    let mut value = usize::from(block[*i]) & mask;
    *i += 1;
    if value < mask {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        if *i >= block.len() {
            return Err(WireParseError::Truncated);
        }
        let byte = block[*i];
        *i += 1;
        value = value
            .checked_add((usize::from(byte & 0x7f)) << shift)
            .ok_or(WireParseError::Truncated)?;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok(value)
}

#[cfg(test)]
#[path = "wire_emit/tests.rs"]
mod tests;
