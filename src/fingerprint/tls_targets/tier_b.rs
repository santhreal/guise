//! Tier-B fingerprint-target loading. Hardcoded fingerprint catalogues are a
//! Tier-B data concern (operators drop new measured real-browser targets to
//! widen the anti-uniqueness cluster); the built-in list is the default, and a
//! dropped TOML file extends it. A malformed file fails closed, no entry is
//! ever silently skipped.

use super::{validate_target_fields, FingerprintTarget, FINGERPRINT_TARGETS};
use std::collections::HashSet;
use std::path::Path;

/// Upper bound on a Tier-B target TOML (64 KiB). A target catalogue is small;
/// this bounds a hostile or accidental oversized drop-in before it is read
/// into memory.
const MAX_TARGETS_TOML_BYTES: u64 = 64 * 1024;

/// Error loading a Tier-B fingerprint-target catalogue. Every variant is a
/// loud, fail-closed outcome (there is no "skipped the bad entry" path).
#[derive(Debug)]
pub enum TargetLoadError {
    /// The file could not be read.
    Read(String),
    /// The file exceeds [`MAX_TARGETS_TOML_BYTES`].
    TooLarge {
        /// The offending path.
        path: String,
        /// Actual size in bytes.
        bytes: u64,
    },
    /// The TOML did not parse.
    Parse(String),
    /// A target's fingerprint fields were malformed (carries label + reason).
    Invalid {
        /// The offending target's label.
        label: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A loaded label collides with another loaded target or a built-in one.
    DuplicateLabel(String),
}

impl std::fmt::Display for TargetLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(e) => write!(f, "tier-b targets: read failed: {e}"),
            Self::TooLarge { path, bytes } => write!(
                f,
                "tier-b targets: {path} is {bytes} bytes, over the {MAX_TARGETS_TOML_BYTES}-byte cap"
            ),
            Self::Parse(e) => write!(f, "tier-b targets: TOML parse failed: {e}"),
            Self::Invalid { label, reason } => {
                write!(f, "tier-b targets: target `{label}` invalid: {reason}")
            }
            Self::DuplicateLabel(label) => {
                write!(f, "tier-b targets: duplicate label `{label}` (already loaded or built-in)")
            }
        }
    }
}

impl std::error::Error for TargetLoadError {}

#[derive(serde::Deserialize)]
struct TargetDoc {
    label: String,
    ja3: String,
    ja4: String,
    akamai_h2: String,
    peet_h2: String,
}

#[derive(serde::Deserialize)]
struct TargetsDoc {
    /// `[[target]]` array-of-tables; empty/absent means "no targets," which
    /// is a successful load of zero targets, not an error.
    #[serde(default)]
    target: Vec<TargetDoc>,
}

/// Load + validate Tier-B fingerprint targets from a TOML file.
///
/// The returned targets' string fields are leaked to `'static` (a load-once
/// catalogue lives for the process), so they slot directly into the cluster
/// API and [`super::builtin_with`]. Every entry is validated with the same
/// [`validate_target_fields`] the built-in audit uses; the first malformed or
/// duplicate entry fails the whole load (fail-closed, never skip).
///
/// # Errors
/// [`TargetLoadError`] on read failure, oversize, parse failure, a malformed
/// target, or a label that duplicates another loaded or built-in target.
pub fn load_targets_from_toml(path: &Path) -> Result<Vec<FingerprintTarget>, TargetLoadError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| TargetLoadError::Read(format!("{}: {e}", path.display())))?;
    if meta.len() > MAX_TARGETS_TOML_BYTES {
        return Err(TargetLoadError::TooLarge {
            path: path.display().to_string(),
            bytes: meta.len(),
        });
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| TargetLoadError::Read(format!("{}: {e}", path.display())))?;
    let doc: TargetsDoc =
        toml::from_str(&raw).map_err(|e| TargetLoadError::Parse(e.to_string()))?;

    let builtin: HashSet<&str> = FINGERPRINT_TARGETS.iter().map(|t| t.label).collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(doc.target.len());
    for d in doc.target {
        validate_target_fields(&d.label, &d.ja3, &d.ja4, &d.akamai_h2, &d.peet_h2).map_err(
            |reason| TargetLoadError::Invalid {
                label: d.label.clone(),
                reason,
            },
        )?;
        if builtin.contains(d.label.as_str()) || !seen.insert(d.label.clone()) {
            return Err(TargetLoadError::DuplicateLabel(d.label));
        }
        out.push(FingerprintTarget {
            label: Box::leak(d.label.into_boxed_str()),
            ja3: Box::leak(d.ja3.into_boxed_str()),
            ja4: Box::leak(d.ja4.into_boxed_str()),
            akamai_h2: Box::leak(d.akamai_h2.into_boxed_str()),
            peet_h2: Box::leak(d.peet_h2.into_boxed_str()),
        });
    }
    Ok(out)
}
