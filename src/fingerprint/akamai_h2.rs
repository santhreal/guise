//! Structured Akamai HTTP/2 fingerprint (G011–G013): parse the published
//! `SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header-order` string into typed
//! fields, canonicalize it back byte-for-byte, and **localize** a divergence to
//! the exact frame field that differs.
//!
//! ## Why structured, not string-equality
//!
//! The catalogue ([`tls_targets`](crate::fingerprint::tls_targets)) and the
//! cluster check ([`cluster`](crate::fingerprint::cluster)) compare the Akamai
//! H2 fingerprint as an opaque string. String-equality is the *correct*
//! membership test, the format is order-sensitive and the bytes are the
//! fingerprint, but when two shapes disagree it can only say "different," not
//! *what* is different. This module is the un-decorator: given an observed H2
//! shape and a target, it reports `INITIAL_WINDOW_SIZE 131072 vs 6291456` or
//! `pseudo-header order m,p,a,s vs m,a,s,p`, the way the cipher-list diagnostic
//! localized the missing `0xc009` suite at L2.
//!
//! It is a screwdriver: it parses and diffs *the operator's own* H2 shape
//! against a reference target. It never decides a remote peer is a browser,
//! never scores, never claims. "These two H2 frames differ in field X" is a
//! structural fact; "this is/ isn't Firefox" is the cluster's membership
//! judgment, computed elsewhere over the whole catalogue.
//!
//! ## Format (Akamai's passive HTTP/2 fingerprint)
//!
//! Four `|`-separated sections, each order-significant:
//! 1. **SETTINGS**: `id:value` pairs joined by `;`, in the order the SETTINGS
//!    frame sent them (the order is itself a tell: Safari sends `2;4;3`). IDs are
//!    the RFC 7540 settings (1 = HEADER_TABLE_SIZE … 6 = MAX_HEADER_LIST_SIZE).
//! 2. **WINDOW_UPDATE**: the connection-level increment, or `0` if none.
//! 3. **PRIORITY**: `stream:exclusive:dependent:weight` frames joined by `,`,
//!    or `0` if none (Firefox 131 sends `3:0:0:201`; Firefox 150 sends none).
//! 4. **Pseudo-header order**: `m`/`p`/`a`/`s` (`:method` `:path` `:authority`
//!    `:scheme`) joined by `,`. Firefox `m,p,a,s`, Chrome `m,a,s,p`, Safari
//!    `m,s,p,a`: a cheap, strong browser-family discriminator.

use std::collections::BTreeMap;
use std::fmt;

/// RFC 7540 HTTP/2 SETTINGS identifiers, for naming the well-known IDs in
/// diagnostics and accessors. The fingerprint preserves whatever numeric IDs
/// were sent (including unknown ones), so the parser stores raw `u16`; these are
/// the human labels.
pub mod setting_id {
    /// `SETTINGS_HEADER_TABLE_SIZE` (HPACK dynamic table size).
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    /// `SETTINGS_ENABLE_PUSH`.
    pub const ENABLE_PUSH: u16 = 0x2;
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`.
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    /// `SETTINGS_INITIAL_WINDOW_SIZE`.
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    /// `SETTINGS_MAX_FRAME_SIZE`.
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`.
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

/// One HTTP/2 SETTINGS entry, preserving the sent order via its position in
/// [`AkamaiH2Fingerprint::settings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2Setting {
    /// The SETTINGS identifier (see [`setting_id`]).
    pub id: u16,
    /// The advertised value.
    pub value: u32,
}

/// One HTTP/2 PRIORITY frame, as Akamai records it
/// (`stream:exclusive:dependent:weight`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2Priority {
    /// The stream the PRIORITY frame applies to.
    pub stream_id: u32,
    /// Exclusive bit (0 or 1).
    pub exclusive: u8,
    /// The stream this one is made dependent on.
    pub dependent: u32,
    /// The priority weight (1–256, sent as the wire value).
    pub weight: u16,
}

/// The four HTTP/2 pseudo-headers, in the order a request sent them. Order is a
/// strong browser-family discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudoHeader {
    /// `:method`
    Method,
    /// `:path`
    Path,
    /// `:authority`
    Authority,
    /// `:scheme`
    Scheme,
}

impl PseudoHeader {
    /// The single-letter Akamai code (`m`/`p`/`a`/`s`).
    #[must_use]
    pub fn code(self) -> char {
        match self {
            Self::Method => 'm',
            Self::Path => 'p',
            Self::Authority => 'a',
            Self::Scheme => 's',
        }
    }

    fn from_code(c: char) -> Option<Self> {
        match c {
            'm' => Some(Self::Method),
            'p' => Some(Self::Path),
            'a' => Some(Self::Authority),
            's' => Some(Self::Scheme),
            _ => None,
        }
    }
}

/// A parse failure. Every variant names the section and the offending token so a
/// malformed catalogue entry or dropped Tier-B target fails **closed** with a
/// reason, never silently degrading to a partial parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AkamaiH2ParseError {
    /// Not exactly four `|`-separated sections.
    SectionCount(usize),
    /// A SETTINGS token was not `id:value`, or a number did not parse.
    Settings(String),
    /// The WINDOW_UPDATE section was not a single integer.
    WindowUpdate(String),
    /// A PRIORITY frame was not `stream:exclusive:dependent:weight`, or a number
    /// did not parse.
    Priority(String),
    /// The pseudo-header section carried an unknown code or no entries.
    PseudoHeader(String),
}

impl fmt::Display for AkamaiH2ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SectionCount(n) => write!(
                f,
                "Akamai H2 fingerprint must have 4 `|`-separated sections, got {n}"
            ),
            Self::Settings(t) => write!(f, "malformed SETTINGS token `{t}` (want `id:value`)"),
            Self::WindowUpdate(t) => write!(f, "malformed WINDOW_UPDATE `{t}` (want one integer)"),
            Self::Priority(t) => write!(
                f,
                "malformed PRIORITY frame `{t}` (want `stream:exclusive:dependent:weight`)"
            ),
            Self::PseudoHeader(t) => {
                write!(f, "malformed pseudo-header section `{t}` (codes m/p/a/s)")
            }
        }
    }
}

impl std::error::Error for AkamaiH2ParseError {}

/// One localized difference between two Akamai H2 shapes. Returned by
/// [`AkamaiH2Fingerprint::diff`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AkamaiH2Divergence {
    /// A SETTINGS value present in one shape differs from (or is absent in) the
    /// other. `observed`/`target` are `None` when the id is absent on that side.
    Setting {
        /// The SETTINGS identifier.
        id: u16,
        /// Value in the observed shape (`None` = not sent).
        observed: Option<u32>,
        /// Value in the target shape (`None` = not sent).
        target: Option<u32>,
    },
    /// The SETTINGS values agree but were sent in a different id order (itself a
    /// tell). Carries the two id sequences.
    SettingsOrder {
        /// Observed id order.
        observed: Vec<u16>,
        /// Target id order.
        target: Vec<u16>,
    },
    /// The connection-level WINDOW_UPDATE increment differs.
    WindowUpdate {
        /// Observed increment.
        observed: u32,
        /// Target increment.
        target: u32,
    },
    /// The PRIORITY frame set differs.
    Priority {
        /// Observed PRIORITY frames.
        observed: Vec<H2Priority>,
        /// Target PRIORITY frames.
        target: Vec<H2Priority>,
    },
    /// The pseudo-header order differs (the strongest cheap discriminator).
    PseudoHeaderOrder {
        /// Observed order.
        observed: Vec<PseudoHeader>,
        /// Target order.
        target: Vec<PseudoHeader>,
    },
}

/// A parsed Akamai HTTP/2 fingerprint. Field order is preserved exactly as
/// parsed so [`to_canonical`](Self::to_canonical) round-trips the source string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkamaiH2Fingerprint {
    /// SETTINGS entries, in sent order.
    pub settings: Vec<H2Setting>,
    /// Connection-level WINDOW_UPDATE increment (`0` = none sent).
    pub window_update: u32,
    /// PRIORITY frames, in sent order (empty = none sent, rendered `0`).
    pub priorities: Vec<H2Priority>,
    /// Pseudo-header order.
    pub pseudo_header_order: Vec<PseudoHeader>,
}

impl AkamaiH2Fingerprint {
    /// Parse a published Akamai H2 fingerprint string. Fails closed on any
    /// malformed section (no partial parse is ever returned).
    ///
    /// # Errors
    /// [`AkamaiH2ParseError`] identifying the section and token at fault.
    pub fn parse(raw: &str) -> Result<Self, AkamaiH2ParseError> {
        let sections: Vec<&str> = raw.split('|').collect();
        if sections.len() != 4 {
            return Err(AkamaiH2ParseError::SectionCount(sections.len()));
        }

        let settings = parse_settings(sections[0])?;

        let window_update: u32 = sections[1]
            .parse()
            .map_err(|_| AkamaiH2ParseError::WindowUpdate(sections[1].to_string()))?;

        let priorities = parse_priorities(sections[2])?;

        let pseudo_header_order = parse_pseudo_headers(sections[3])?;

        Ok(Self {
            settings,
            window_update,
            priorities,
            pseudo_header_order,
        })
    }

    /// Re-serialize to the canonical Akamai string. Round-trips
    /// [`parse`](Self::parse): `parse(s).to_canonical() == s` for every
    /// well-formed `s`.
    #[must_use]
    pub fn to_canonical(&self) -> String {
        let settings = self
            .settings
            .iter()
            .map(|s| format!("{}:{}", s.id, s.value))
            .collect::<Vec<_>>()
            .join(";");
        let priorities = if self.priorities.is_empty() {
            "0".to_string()
        } else {
            self.priorities
                .iter()
                .map(|p| {
                    format!(
                        "{}:{}:{}:{}",
                        p.stream_id, p.exclusive, p.dependent, p.weight
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        let pseudo = self
            .pseudo_header_order
            .iter()
            .map(|p| p.code().to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!("{settings}|{}|{priorities}|{pseudo}", self.window_update)
    }

    /// The value advertised for a SETTINGS id, if it was sent.
    #[must_use]
    pub fn setting(&self, id: u16) -> Option<u32> {
        self.settings.iter().find(|s| s.id == id).map(|s| s.value)
    }

    /// `SETTINGS_HEADER_TABLE_SIZE`, if sent.
    #[must_use]
    pub fn header_table_size(&self) -> Option<u32> {
        self.setting(setting_id::HEADER_TABLE_SIZE)
    }

    /// `SETTINGS_ENABLE_PUSH`, if sent.
    #[must_use]
    pub fn enable_push(&self) -> Option<u32> {
        self.setting(setting_id::ENABLE_PUSH)
    }

    /// `SETTINGS_MAX_CONCURRENT_STREAMS`, if sent.
    #[must_use]
    pub fn max_concurrent_streams(&self) -> Option<u32> {
        self.setting(setting_id::MAX_CONCURRENT_STREAMS)
    }

    /// `SETTINGS_INITIAL_WINDOW_SIZE`, if sent.
    #[must_use]
    pub fn initial_window_size(&self) -> Option<u32> {
        self.setting(setting_id::INITIAL_WINDOW_SIZE)
    }

    /// `SETTINGS_MAX_FRAME_SIZE`, if sent.
    #[must_use]
    pub fn max_frame_size(&self) -> Option<u32> {
        self.setting(setting_id::MAX_FRAME_SIZE)
    }

    /// `SETTINGS_MAX_HEADER_LIST_SIZE`, if sent.
    #[must_use]
    pub fn max_header_list_size(&self) -> Option<u32> {
        self.setting(setting_id::MAX_HEADER_LIST_SIZE)
    }

    /// True when both shapes are byte-identical in every field (order included).
    /// Equivalent to canonical-string equality, but typed.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.diff(other).is_empty()
    }

    /// Localize every field in which `self` (observed) differs from `target`.
    /// Empty ⇔ [`matches`](Self::matches). Order-sensitive, matching the
    /// catalogue's string-equality membership test.
    #[must_use]
    pub fn diff(&self, target: &Self) -> Vec<AkamaiH2Divergence> {
        let mut out = Vec::new();

        // SETTINGS values, by id, over the union, a present/absent or value
        // mismatch is reported per id.
        let self_map: BTreeMap<u16, u32> = self.settings.iter().map(|s| (s.id, s.value)).collect();
        let target_map: BTreeMap<u16, u32> =
            target.settings.iter().map(|s| (s.id, s.value)).collect();
        let mut ids: Vec<u16> = self_map.keys().chain(target_map.keys()).copied().collect();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            let o = self_map.get(&id).copied();
            let t = target_map.get(&id).copied();
            if o != t {
                out.push(AkamaiH2Divergence::Setting {
                    id,
                    observed: o,
                    target: t,
                });
            }
        }
        // Same value-set but different sent order is itself a tell.
        if self_map == target_map {
            let self_order: Vec<u16> = self.settings.iter().map(|s| s.id).collect();
            let target_order: Vec<u16> = target.settings.iter().map(|s| s.id).collect();
            if self_order != target_order {
                out.push(AkamaiH2Divergence::SettingsOrder {
                    observed: self_order,
                    target: target_order,
                });
            }
        }

        if self.window_update != target.window_update {
            out.push(AkamaiH2Divergence::WindowUpdate {
                observed: self.window_update,
                target: target.window_update,
            });
        }

        if self.priorities != target.priorities {
            out.push(AkamaiH2Divergence::Priority {
                observed: self.priorities.clone(),
                target: target.priorities.clone(),
            });
        }

        if self.pseudo_header_order != target.pseudo_header_order {
            out.push(AkamaiH2Divergence::PseudoHeaderOrder {
                observed: self.pseudo_header_order.clone(),
                target: target.pseudo_header_order.clone(),
            });
        }

        out
    }
}

fn parse_settings(section: &str) -> Result<Vec<H2Setting>, AkamaiH2ParseError> {
    if section.is_empty() {
        return Ok(Vec::new());
    }
    section
        .split(';')
        .map(|tok| {
            let (id, value) = tok
                .split_once(':')
                .ok_or_else(|| AkamaiH2ParseError::Settings(tok.to_string()))?;
            let id: u16 = id
                .parse()
                .map_err(|_| AkamaiH2ParseError::Settings(tok.to_string()))?;
            let value: u32 = value
                .parse()
                .map_err(|_| AkamaiH2ParseError::Settings(tok.to_string()))?;
            Ok(H2Setting { id, value })
        })
        .collect()
}

fn parse_priorities(section: &str) -> Result<Vec<H2Priority>, AkamaiH2ParseError> {
    // `0` is the documented "no PRIORITY frames" sentinel.
    if section == "0" || section.is_empty() {
        return Ok(Vec::new());
    }
    section
        .split(',')
        .map(|frame| {
            let parts: Vec<&str> = frame.split(':').collect();
            if parts.len() != 4 {
                return Err(AkamaiH2ParseError::Priority(frame.to_string()));
            }
            let stream_id: u32 = parts[0]
                .parse()
                .map_err(|_| AkamaiH2ParseError::Priority(frame.to_string()))?;
            let exclusive: u8 = parts[1]
                .parse()
                .map_err(|_| AkamaiH2ParseError::Priority(frame.to_string()))?;
            let dependent: u32 = parts[2]
                .parse()
                .map_err(|_| AkamaiH2ParseError::Priority(frame.to_string()))?;
            let weight: u16 = parts[3]
                .parse()
                .map_err(|_| AkamaiH2ParseError::Priority(frame.to_string()))?;
            Ok(H2Priority {
                stream_id,
                exclusive,
                dependent,
                weight,
            })
        })
        .collect()
}

fn parse_pseudo_headers(section: &str) -> Result<Vec<PseudoHeader>, AkamaiH2ParseError> {
    if section.is_empty() {
        return Err(AkamaiH2ParseError::PseudoHeader(section.to_string()));
    }
    section
        .split(',')
        .map(|tok| {
            let mut chars = tok.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => PseudoHeader::from_code(c)
                    .ok_or_else(|| AkamaiH2ParseError::PseudoHeader(tok.to_string())),
                _ => Err(AkamaiH2ParseError::PseudoHeader(tok.to_string())),
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "akamai_h2/tests.rs"]
mod tests;
