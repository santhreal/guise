//! Tier-B speech-synthesis voice persona library (G099).
//!
//! Real browsers expose a list of speech-synthesis voices via
//! `speechSynthesis.getVoices()`. The exact set and names are browser- and
//! platform-specific, making them a subtle fingerprint. This loader lets an
//! operator maintain platform-typical voice lists from TOML drop-ins without
//! recompiling, so the voice persona stays coherent with the claimed OS.
//!
//! A malformed file fails closed (Law 10): the first bad entry rejects the whole
//! load, no voice is ever silently skipped, because a skipped entry would
//! create a coverage hole in the voice fingerprint.

/// One speech-synthesis voice entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoicePersona {
    /// Display name (e.g. `"Samantha"`).
    pub name: &'static str,
    /// BCP 47 language tag (e.g. `"en-US"`).
    pub lang: &'static str,
    /// Whether this voice is the platform default.
    pub default: bool,
}

#[cfg(feature = "tier-b-toml")]
mod loader_impl {
    use super::VoicePersona;
    use std::path::Path;

    /// Upper bound on a Tier-B voice TOML (64 KiB).
    const MAX_VOICE_TOML_BYTES: u64 = 64 * 1024;

    /// Error loading a Tier-B voice persona library. Every variant is a loud,
    /// fail-closed outcome.
    #[derive(Debug)]
    pub enum VoiceLoadError {
        /// The file could not be read.
        Read(String),
        /// The file exceeds [`MAX_VOICE_TOML_BYTES`].
        TooLarge {
            /// The offending path.
            path: String,
            /// Actual size in bytes.
            bytes: u64,
        },
        /// The TOML did not parse.
        Parse(String),
        /// A voice entry was malformed (carries index + reason).
        Invalid {
            /// One-based entry index in the file.
            index: usize,
            /// Why it was rejected.
            reason: String,
        },
    }

    impl std::fmt::Display for VoiceLoadError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Read(e) => write!(f, "tier-b voices: read failed: {e}"),
                Self::TooLarge { path, bytes } => write!(
                    f,
                    "tier-b voices: {path} is {bytes} bytes, over the {MAX_VOICE_TOML_BYTES}-byte cap"
                ),
                Self::Parse(e) => write!(f, "tier-b voices: TOML parse failed: {e}"),
                Self::Invalid { index, reason } => {
                    write!(f, "tier-b voices: entry #{index} invalid: {reason}")
                }
            }
        }
    }

    impl std::error::Error for VoiceLoadError {}

    #[derive(serde::Deserialize)]
    struct VoiceDoc {
        name: String,
        lang: String,
        #[serde(default)]
        default: bool,
    }

    #[derive(serde::Deserialize)]
    struct VoicesDoc {
        /// `[[voice]]` array-of-tables; empty/absent is a successful load of zero
        /// voices, not an error.
        #[serde(default)]
        voice: Vec<VoiceDoc>,
    }

    /// Load + validate Tier-B speech-synthesis voice personas from a TOML file.
    ///
    /// Every entry is validated: non-empty name and a non-empty, plausibly
    /// formatted BCP 47 lang tag. The first malformed entry fails the whole load
    /// (fail-closed).
    ///
    /// # Errors
    /// [`VoiceLoadError`] on read failure, oversize, parse failure, or a
    /// malformed voice entry.
    pub fn load_voices_from_toml(path: &Path) -> Result<Vec<VoicePersona>, VoiceLoadError> {
        let meta = std::fs::metadata(path)
            .map_err(|e| VoiceLoadError::Read(format!("{}: {e}", path.display())))?;
        if meta.len() > MAX_VOICE_TOML_BYTES {
            return Err(VoiceLoadError::TooLarge {
                path: path.display().to_string(),
                bytes: meta.len(),
            });
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| VoiceLoadError::Read(format!("{}: {e}", path.display())))?;
        let doc: VoicesDoc =
            toml::from_str(&raw).map_err(|e| VoiceLoadError::Parse(e.to_string()))?;

        let mut out = Vec::with_capacity(doc.voice.len());
        for (idx, d) in doc.voice.into_iter().enumerate() {
            let index = idx + 1;
            let invalid = |reason: &str| VoiceLoadError::Invalid {
                index,
                reason: reason.to_string(),
            };

            let name = d.name.trim();
            let lang = d.lang.trim();
            if name.is_empty() {
                return Err(invalid("empty name"));
            }
            if lang.is_empty() {
                return Err(invalid("empty lang"));
            }
            // Plausibility: a BCP 47 tag has at least a 2-letter primary subtag
            // and no spaces.
            if lang.contains(' ') || lang.len() < 2 {
                return Err(invalid(&format!(
                    "lang `{lang}` is not a plausible BCP 47 tag"
                )));
            }

            out.push(VoicePersona {
                name: Box::leak(name.to_string().into_boxed_str()),
                lang: Box::leak(lang.to_string().into_boxed_str()),
                default: d.default,
            });
        }
        Ok(out)
    }

    /// Load every `*.toml` file in a Tier-B voice directory, merging them into
    /// one pooled library. Files are processed in lexicographic order; the first
    /// malformed file fails the whole load.
    pub fn load_voice_directory(path: &Path) -> Result<Vec<VoicePersona>, VoiceLoadError> {
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| VoiceLoadError::Read(format!("{}: {e}", path.display())))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
            })
            .map(|e| e.path())
            .collect();
        entries.sort();

        let mut out = Vec::new();
        for path in entries {
            out.extend(load_voices_from_toml(&path)?);
        }
        Ok(out)
    }
}

#[cfg(feature = "tier-b-toml")]
pub use loader_impl::{load_voice_directory, load_voices_from_toml, VoiceLoadError};

#[cfg(all(test, feature = "tier-b-toml"))]
#[path = "voice_tier_b/tests.rs"]
mod tests;
