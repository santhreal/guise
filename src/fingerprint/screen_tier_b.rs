//! Tier-B screen / DPR persona library (G097).
//!
//! Built-in profiles ship a small set of screen dimensions and color depths in
//! `ProfileFacts` and `ProfileHardware`. This loader lets an operator extend or
//! replace that set from TOML drop-ins without recompiling, so the persona pool
//! can track real device resolutions and Retina-scale DPR values.
//!
//! A malformed file fails closed (Law 10): the first bad entry rejects the whole
//! load, no screen persona is ever silently skipped, because a skipped entry
//! would create a coverage hole in the screen/DPR fingerprint.

/// One screen / DPR persona.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScreenPersona {
    /// Screen width in CSS pixels (`screen.width`).
    pub width: u32,
    /// Screen height in CSS pixels (`screen.height`).
    pub height: u32,
    /// Device pixel ratio (`window.devicePixelRatio`).
    pub dpr: f64,
    /// Screen color depth (`screen.colorDepth` / `screen.pixelDepth`).
    pub color_depth: u8,
}

impl ScreenPersona {
    /// Approximate physical pixel width (CSS width * DPR).
    #[must_use]
    pub fn physical_width(&self) -> u64 {
        (self.width as f64 * self.dpr).round() as u64
    }

    /// Approximate physical pixel height (CSS height * DPR).
    #[must_use]
    pub fn physical_height(&self) -> u64 {
        (self.height as f64 * self.dpr).round() as u64
    }

    /// Whether this persona represents a mobile-sized viewport.
    #[must_use]
    pub fn is_mobile(&self) -> bool {
        self.width < 600 || self.height < 600
    }
}

#[cfg(feature = "tier-b-toml")]
mod loader_impl {
    use super::ScreenPersona;
    use std::path::Path;

    /// Upper bound on a Tier-B screen TOML (64 KiB).
    const MAX_SCREEN_TOML_BYTES: u64 = 64 * 1024;

    /// Error loading a Tier-B screen persona library. Every variant is a loud,
    /// fail-closed outcome.
    #[derive(Debug)]
    pub enum ScreenLoadError {
        /// The file could not be read.
        Read(String),
        /// The file exceeds [`MAX_SCREEN_TOML_BYTES`].
        TooLarge {
            /// The offending path.
            path: String,
            /// Actual size in bytes.
            bytes: u64,
        },
        /// The TOML did not parse.
        Parse(String),
        /// A screen entry was malformed (carries index + reason).
        Invalid {
            /// One-based entry index in the file.
            index: usize,
            /// Why it was rejected.
            reason: String,
        },
    }

    impl std::fmt::Display for ScreenLoadError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Read(e) => write!(f, "tier-b screen: read failed: {e}"),
                Self::TooLarge { path, bytes } => write!(
                    f,
                    "tier-b screen: {path} is {bytes} bytes, over the {MAX_SCREEN_TOML_BYTES}-byte cap"
                ),
                Self::Parse(e) => write!(f, "tier-b screen: TOML parse failed: {e}"),
                Self::Invalid { index, reason } => {
                    write!(f, "tier-b screen: entry #{index} invalid: {reason}")
                }
            }
        }
    }

    impl std::error::Error for ScreenLoadError {}

    #[derive(serde::Deserialize)]
    struct ScreenDoc {
        width: u32,
        height: u32,
        dpr: f64,
        color_depth: u8,
    }

    #[derive(serde::Deserialize)]
    struct ScreensDoc {
        /// `[[screen]]` array-of-tables; empty/absent is a successful load of zero
        /// screens, not an error.
        #[serde(default)]
        screen: Vec<ScreenDoc>,
    }

    /// Load + validate Tier-B screen/DPR personas from a TOML file.
    ///
    /// Every entry is validated: positive width/height, positive DPR, and a
    /// color depth of 8, 16, 24, or 30 bits. The first malformed entry fails the
    /// whole load (fail-closed).
    ///
    /// # Errors
    /// [`ScreenLoadError`] on read failure, oversize, parse failure, or a
    /// malformed screen entry.
    pub fn load_screens_from_toml(path: &Path) -> Result<Vec<ScreenPersona>, ScreenLoadError> {
        let meta = std::fs::metadata(path)
            .map_err(|e| ScreenLoadError::Read(format!("{}: {e}", path.display())))?;
        if meta.len() > MAX_SCREEN_TOML_BYTES {
            return Err(ScreenLoadError::TooLarge {
                path: path.display().to_string(),
                bytes: meta.len(),
            });
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| ScreenLoadError::Read(format!("{}: {e}", path.display())))?;
        let doc: ScreensDoc =
            toml::from_str(&raw).map_err(|e| ScreenLoadError::Parse(e.to_string()))?;

        let mut out = Vec::with_capacity(doc.screen.len());
        for (idx, d) in doc.screen.into_iter().enumerate() {
            let index = idx + 1;
            let invalid = |reason: &str| ScreenLoadError::Invalid {
                index,
                reason: reason.to_string(),
            };

            if d.width == 0 {
                return Err(invalid("width must be > 0"));
            }
            if d.height == 0 {
                return Err(invalid("height must be > 0"));
            }
            if d.dpr <= 0.0 || !d.dpr.is_finite() {
                return Err(invalid("dpr must be a positive finite number"));
            }
            if ![8u8, 16, 24, 30].contains(&d.color_depth) {
                return Err(invalid(&format!(
                    "color_depth {} is not a realistic display depth (8/16/24/30)",
                    d.color_depth
                )));
            }

            out.push(ScreenPersona {
                width: d.width,
                height: d.height,
                dpr: d.dpr,
                color_depth: d.color_depth,
            });
        }
        Ok(out)
    }

    /// Load every `*.toml` file in a Tier-B screen directory, merging them into
    /// one pooled library. Files are processed in lexicographic order; the first
    /// malformed file fails the whole load.
    pub fn load_screen_directory(path: &Path) -> Result<Vec<ScreenPersona>, ScreenLoadError> {
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| ScreenLoadError::Read(format!("{}: {e}", path.display())))?
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
            out.extend(load_screens_from_toml(&path)?);
        }
        Ok(out)
    }
}

#[cfg(feature = "tier-b-toml")]
pub use loader_impl::{load_screen_directory, load_screens_from_toml, ScreenLoadError};

#[cfg(all(test, feature = "tier-b-toml"))]
#[path = "screen_tier_b/tests.rs"]
mod tests;
