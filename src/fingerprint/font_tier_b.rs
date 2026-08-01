//! Tier-B system font persona library (G096).
//!
//! Built-in profiles ship a small, coherent set of standard Linux font families
//! that the reynard engine maps to `font.system.whitelist`. The
//! [`LINUX_STANDARD_FONTS`] const is always available for consumers (including
//! the reynard launch path). When the `tier-b-toml` feature is active, the
//! `load_*` functions let operators extend or replace that set from TOML drop-ins
//! without recompiling.
//!
//! A malformed file fails closed (Law 10): the first bad entry rejects the whole
//! load, no font is ever silently skipped, because a skipped entry would create
//! a coverage hole in the font persona.

/// The built-in Linux standard font set, mirrored as a Tier-B data file under
/// `tier_b/fonts/linux_standard.toml`. Keeping the const and the file in sync
/// is enforced by `built_in_font_set_matches_tier_b_file` when the `tier-b-toml`
/// feature is active.
pub const LINUX_STANDARD_FONTS: &[&str] = &[
    "DejaVu Sans",
    "DejaVu Serif",
    "DejaVu Sans Mono",
    "Liberation Sans",
    "Liberation Serif",
    "Liberation Mono",
    "Noto Sans",
    "Noto Serif",
    "Noto Mono",
    "Noto Color Emoji",
    "FreeSans",
    "FreeSerif",
    "FreeMono",
    "Cantarell",
    "Droid Sans Fallback",
];

#[cfg(feature = "tier-b-toml")]
mod loader_impl {
    use std::path::Path;

    /// Upper bound on a Tier-B font TOML (64 KiB). The library is small text data;
    /// this bounds a hostile or accidental oversized drop-in.
    const MAX_FONT_TOML_BYTES: u64 = 64 * 1024;

    /// One font family entry in a Tier-B font persona.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FontPersona {
        /// Font family name (e.g. `"DejaVu Sans"`).
        pub family: &'static str,
    }

    /// Error loading a Tier-B font persona library. Every variant is a loud,
    /// fail-closed outcome.
    #[derive(Debug)]
    pub enum FontLoadError {
        /// The file could not be read.
        Read(String),
        /// The file exceeds [`MAX_FONT_TOML_BYTES`].
        TooLarge {
            /// The offending path.
            path: String,
            /// Actual size in bytes.
            bytes: u64,
        },
        /// The TOML did not parse.
        Parse(String),
        /// A font entry was malformed (carries index + reason).
        Invalid {
            /// One-based entry index in the file.
            index: usize,
            /// Why it was rejected.
            reason: String,
        },
    }

    impl std::fmt::Display for FontLoadError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Read(e) => write!(f, "tier-b fonts: read failed: {e}"),
                Self::TooLarge { path, bytes } => write!(
                    f,
                    "tier-b fonts: {path} is {bytes} bytes, over the {MAX_FONT_TOML_BYTES}-byte cap"
                ),
                Self::Parse(e) => write!(f, "tier-b fonts: TOML parse failed: {e}"),
                Self::Invalid { index, reason } => {
                    write!(f, "tier-b fonts: entry #{index} invalid: {reason}")
                }
            }
        }
    }

    impl std::error::Error for FontLoadError {}

    #[derive(serde::Deserialize)]
    struct FontDoc {
        family: String,
    }

    #[derive(serde::Deserialize)]
    struct FontsDoc {
        /// `[[font]]` array-of-tables; empty/absent is a successful load of zero
        /// fonts, not an error.
        #[serde(default)]
        font: Vec<FontDoc>,
    }

    /// Load + validate Tier-B font personas from a TOML file.
    ///
    /// The returned strings are leaked to `'static` (a load-once library lives for
    /// the process), so each [`FontPersona`] can be used anywhere the built-in font
    /// strings are.
    ///
    /// Every entry is validated: a non-empty family name. The first malformed entry
    /// fails the whole load (fail-closed).
    ///
    /// # Errors
    /// [`FontLoadError`] on read failure, oversize, parse failure, or a malformed
    /// font entry.
    pub fn load_fonts_from_toml(path: &Path) -> Result<Vec<FontPersona>, FontLoadError> {
        let meta = std::fs::metadata(path)
            .map_err(|e| FontLoadError::Read(format!("{}: {e}", path.display())))?;
        if meta.len() > MAX_FONT_TOML_BYTES {
            return Err(FontLoadError::TooLarge {
                path: path.display().to_string(),
                bytes: meta.len(),
            });
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| FontLoadError::Read(format!("{}: {e}", path.display())))?;
        let doc: FontsDoc =
            toml::from_str(&raw).map_err(|e| FontLoadError::Parse(e.to_string()))?;

        let mut out = Vec::with_capacity(doc.font.len());
        for (idx, d) in doc.font.into_iter().enumerate() {
            let index = idx + 1;
            let invalid = |reason: &str| FontLoadError::Invalid {
                index,
                reason: reason.to_string(),
            };

            let family = d.family.trim();
            if family.is_empty() {
                return Err(invalid("empty family"));
            }

            out.push(FontPersona {
                family: Box::leak(family.to_string().into_boxed_str()),
            });
        }
        Ok(out)
    }

    /// Load every `*.toml` file in a Tier-B font directory, merging them into one
    /// pooled font library. Files are processed in lexicographic order; the first
    /// malformed file fails the whole load.
    pub fn load_font_directory(path: &Path) -> Result<Vec<FontPersona>, FontLoadError> {
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| FontLoadError::Read(format!("{}: {e}", path.display())))?
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
            out.extend(load_fonts_from_toml(&path)?);
        }
        Ok(out)
    }

    /// Built-in validation: the hardcoded const must equal the Tier-B file so the
    /// two sources never drift.
    #[cfg(test)]
    pub fn built_in_matches_file() -> Result<(), String> {
        use super::LINUX_STANDARD_FONTS;
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = manifest
            .join("tier_b")
            .join("fonts")
            .join("linux_standard.toml");
        let loaded = load_fonts_from_toml(&path).map_err(|e| e.to_string())?;
        let loaded_families: Vec<_> = loaded.iter().map(|f| f.family).collect();
        let built_in: Vec<_> = LINUX_STANDARD_FONTS.to_vec();
        if loaded_families != built_in {
            return Err(format!(
                "Tier-B file and LINUX_STANDARD_FONTS drifted:\nfile: {loaded_families:?}\nconst: {built_in:?}"
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "tier-b-toml")]
pub use loader_impl::{load_font_directory, load_fonts_from_toml, FontLoadError, FontPersona};

#[cfg(all(test, feature = "tier-b-toml"))]
#[path = "font_tier_b/tests.rs"]
mod tests;
