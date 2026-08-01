//! Tier-B TCP/IP stack loading (G020/X044). The five built-in OS-*family*
//! stacks in `guise-profiles::os_network` are the always-available default,
//! keyed by [`UserAgentPlatform`]; this loader lets an operator drop a TOML file
//! to add finer-grained, *labelled* stacks, per-OS-version or per-OEM
//! (`windows-11`, `macos-14`, `android-13-pixel`), without recompiling, the
//! same Tier-B data contract the TLS fingerprint targets use.
//!
//! A malformed file fails closed (Law 10): the first bad or duplicate entry
//! rejects the whole load, no stack is ever silently skipped, because a skipped
//! TCP stack is an invisible coverage hole at the layer detectors probe.
//!
//! Each loaded stack is validated against the SAME invariants the built-in
//! catalogue is proven to satisfy: a canonical initial TTL that survives a
//! zero-hop de-hop, and an options layout that renders a faithful JA4T (reusing
//! [`OsNetworkStack::ja4t`]'s fail-closed IANA option-kind mapping rather than
//! re-implementing it).

use crate::fingerprint::{
    infer_initial_ttl, OsNetworkStack, TcpWindow, UserAgentPlatform, KNOWN_INITIAL_TTLS,
};
use std::collections::HashSet;
use std::path::Path;

/// Upper bound on a Tier-B TCP-stack TOML (64 KiB). The catalogue is small; this
/// bounds a hostile or accidental oversized drop-in before it is read.
const MAX_TCP_STACK_TOML_BYTES: u64 = 64 * 1024;

/// A label paired with the TCP/IP stack it names, loaded from Tier-B data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabeledTcpStack {
    /// Operator-chosen stable label (e.g. `windows-11`, `android-13-pixel`).
    pub label: &'static str,
    /// The TCP/IP SYN stack this label resolves to.
    pub stack: OsNetworkStack,
}

/// Error loading a Tier-B TCP-stack catalogue. Every variant is a loud,
/// fail-closed outcome (there is no "skipped the bad entry" path).
#[derive(Debug)]
pub enum TcpStackLoadError {
    /// The file could not be read.
    Read(String),
    /// The file exceeds [`MAX_TCP_STACK_TOML_BYTES`].
    TooLarge {
        /// The offending path.
        path: String,
        /// Actual size in bytes.
        bytes: u64,
    },
    /// The TOML did not parse.
    Parse(String),
    /// A stack's fields were malformed (carries label + reason).
    Invalid {
        /// The offending stack's label.
        label: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A loaded label collides with another loaded stack.
    DuplicateLabel(String),
}

impl std::fmt::Display for TcpStackLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(e) => write!(f, "tier-b tcp-stacks: read failed: {e}"),
            Self::TooLarge { path, bytes } => write!(
                f,
                "tier-b tcp-stacks: {path} is {bytes} bytes, over the {MAX_TCP_STACK_TOML_BYTES}-byte cap"
            ),
            Self::Parse(e) => write!(f, "tier-b tcp-stacks: TOML parse failed: {e}"),
            Self::Invalid { label, reason } => {
                write!(f, "tier-b tcp-stacks: stack `{label}` invalid: {reason}")
            }
            Self::DuplicateLabel(label) => {
                write!(f, "tier-b tcp-stacks: duplicate label `{label}`")
            }
        }
    }
}

impl std::error::Error for TcpStackLoadError {}

#[derive(serde::Deserialize)]
struct StackDoc {
    label: String,
    /// OS family: `windows` / `linux` / `macos` / `ios` / `android`.
    os: String,
    initial_ttl: u8,
    tcp_mss: u16,
    tcp_window_scale: u8,
    /// `mss-scaled` (autotuned) or a decimal fixed window (e.g. `65535`).
    tcp_window: String,
    tcp_options_layout: String,
    df: bool,
}

#[derive(serde::Deserialize)]
struct StacksDoc {
    /// `[[stack]]` array-of-tables; empty/absent is a successful load of zero
    /// stacks, not an error.
    #[serde(default)]
    stack: Vec<StackDoc>,
}

fn parse_platform(raw: &str) -> Option<UserAgentPlatform> {
    match raw.to_ascii_lowercase().as_str() {
        "windows" => Some(UserAgentPlatform::Windows),
        "linux" => Some(UserAgentPlatform::Linux),
        "macos" | "mac" => Some(UserAgentPlatform::MacOs),
        "ios" => Some(UserAgentPlatform::Ios),
        "android" => Some(UserAgentPlatform::Android),
        _ => None,
    }
}

fn parse_window(raw: &str) -> Option<TcpWindow> {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("mss-scaled") || trimmed == "*" {
        return Some(TcpWindow::MssScaled);
    }
    trimmed.parse::<u16>().ok().map(TcpWindow::Fixed)
}

/// Load + validate Tier-B TCP/IP stacks from a TOML file.
///
/// The returned labels and option-layout strings are leaked to `'static` (a
/// load-once catalogue lives for the process), so each [`LabeledTcpStack`]
/// carries a real [`OsNetworkStack`] usable anywhere the built-in stacks are
/// including [`OsNetworkStack::p0f_signature`] / [`OsNetworkStack::ja4t`].
///
/// Every entry is validated to the built-in catalogue's invariants: a known OS
/// family, a canonical initial TTL that survives a zero-hop de-hop, a non-empty
/// options layout that renders a faithful JA4T, and a parseable window. The
/// first malformed or duplicate entry fails the whole load (fail-closed).
///
/// # Errors
/// [`TcpStackLoadError`] on read failure, oversize, parse failure, a malformed
/// stack, or a label that duplicates another loaded stack.
pub fn load_tcp_stacks_from_toml(path: &Path) -> Result<Vec<LabeledTcpStack>, TcpStackLoadError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| TcpStackLoadError::Read(format!("{}: {e}", path.display())))?;
    if meta.len() > MAX_TCP_STACK_TOML_BYTES {
        return Err(TcpStackLoadError::TooLarge {
            path: path.display().to_string(),
            bytes: meta.len(),
        });
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| TcpStackLoadError::Read(format!("{}: {e}", path.display())))?;
    let doc: StacksDoc =
        toml::from_str(&raw).map_err(|e| TcpStackLoadError::Parse(e.to_string()))?;

    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(doc.stack.len());
    for d in doc.stack {
        let invalid = |reason: &str| TcpStackLoadError::Invalid {
            label: d.label.clone(),
            reason: reason.to_string(),
        };

        let os = parse_platform(&d.os)
            .filter(|p| *p != UserAgentPlatform::Unknown)
            .ok_or_else(|| invalid(&format!("unknown OS family `{}`", d.os)))?;
        if !KNOWN_INITIAL_TTLS.contains(&d.initial_ttl) {
            return Err(invalid(&format!(
                "initial_ttl {} is not a canonical OS default {KNOWN_INITIAL_TTLS:?}",
                d.initial_ttl
            )));
        }
        if infer_initial_ttl(d.initial_ttl) != d.initial_ttl {
            return Err(invalid("initial_ttl does not survive a zero-hop de-hop"));
        }
        if d.tcp_options_layout.trim().is_empty() {
            return Err(invalid("empty tcp_options_layout"));
        }
        let tcp_window = parse_window(&d.tcp_window)
            .ok_or_else(|| invalid(&format!("unparseable tcp_window `{}`", d.tcp_window)))?;

        let layout: &'static str = Box::leak(d.tcp_options_layout.into_boxed_str());
        let stack = OsNetworkStack {
            os,
            initial_ttl: d.initial_ttl,
            tcp_mss: d.tcp_mss,
            tcp_window_scale: d.tcp_window_scale,
            tcp_window,
            tcp_options_layout: layout,
            df: d.df,
        };
        // Reuse JA4T's fail-closed IANA option-kind mapping to reject a layout
        // with an unknown option token (never accept a stack we cannot render).
        if let Err(e) = stack.ja4t() {
            return Err(invalid(&format!(
                "options layout yields no faithful JA4T: {e}"
            )));
        }

        if !seen.insert(d.label.clone()) {
            return Err(TcpStackLoadError::DuplicateLabel(d.label));
        }
        out.push(LabeledTcpStack {
            label: Box::leak(d.label.into_boxed_str()),
            stack,
        });
    }
    Ok(out)
}

#[cfg(test)]
#[path = "os_network_tier_b/tests.rs"]
mod tests;
