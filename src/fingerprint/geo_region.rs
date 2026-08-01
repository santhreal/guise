//! Geo region: the single source of truth for every geography-derived persona
//! surface (G127).
//!
//! A [`GeoRegion`] owns a timezone, locale, language list, representative
//! coordinates, and the egress country used for proxy-geo and WebRTC coherence.
//! Every shipped persona picks **one** region and derives all five surfaces from
//! it, so they cannot drift apart (e.g. `America/New_York` with a German locale or
//! a Japanese proxy).
//!
//! The built-in table covers the zones the shipped personas need. Operators can
//! extend it via Tier-B TOML drop-ins under `tier_b/geo_regions/` without
//! recompiling.

use serde::Serialize;

/// One coherent geographic region. Every geography-derived browser surface for a
/// persona comes from this single row.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct GeoRegion {
    /// Human-readable label, e.g. `"US East"`.
    pub name: &'static str,
    /// IANA timezone identifier, e.g. `"America/New_York"`.
    pub timezone: &'static str,
    /// Primary BCP-47 locale, e.g. `"en-US"`.
    pub locale: &'static str,
    /// Ordered `navigator.languages` values.
    pub languages: &'static [&'static str],
    /// Representative latitude in decimal degrees.
    pub lat: f64,
    /// Representative longitude in decimal degrees.
    pub lon: f64,
    /// ISO-3166-1 alpha-2 country used for proxy-geo and WebRTC coherence,
    /// e.g. `"US"`.
    pub country: &'static str,
}

impl GeoRegion {
    /// The BCP-47 region subtag of [`Self::locale`], uppercased, e.g. `"en-US"`
    /// → `"US"`.
    #[must_use]
    pub fn locale_region(&self) -> Option<String> {
        self.locale
            .split(['-', '_'])
            .nth(1)
            .filter(|r| r.len() == 2 && r.chars().all(|c| c.is_ascii_alphabetic()))
            .map(|r| r.to_ascii_uppercase())
    }

    /// The primary language subtag of [`Self::locale`], lowercased.
    #[must_use]
    pub fn primary_language(&self) -> String {
        self.locale
            .split(['-', '_'])
            .next()
            .unwrap_or(self.locale)
            .to_ascii_lowercase()
    }
}

/// Built-in coherent geo regions. These are the canonical presets the shipped
/// personas draw from.
pub const GEO_REGIONS: &[GeoRegion] = &[
    GeoRegion {
        name: "US East",
        timezone: "America/New_York",
        locale: "en-US",
        languages: &["en-US", "en"],
        lat: 40.7128,
        lon: -74.0060,
        country: "US",
    },
    GeoRegion {
        name: "US Central",
        timezone: "America/Chicago",
        locale: "en-US",
        languages: &["en-US", "en"],
        lat: 41.8781,
        lon: -87.6298,
        country: "US",
    },
    GeoRegion {
        name: "US West",
        timezone: "America/Los_Angeles",
        locale: "en-US",
        languages: &["en-US", "en"],
        lat: 37.7749,
        lon: -122.4194,
        country: "US",
    },
    GeoRegion {
        name: "EU Germany",
        timezone: "Europe/Berlin",
        locale: "de-DE",
        languages: &["de-DE", "de", "en"],
        lat: 52.5200,
        lon: 13.4050,
        country: "DE",
    },
    GeoRegion {
        name: "EU UK",
        timezone: "Europe/London",
        locale: "en-GB",
        languages: &["en-GB", "en"],
        lat: 51.5074,
        lon: -0.1278,
        country: "GB",
    },
    GeoRegion {
        name: "EU France",
        timezone: "Europe/Paris",
        locale: "fr-FR",
        languages: &["fr-FR", "fr", "en"],
        lat: 48.8566,
        lon: 2.3522,
        country: "FR",
    },
    GeoRegion {
        name: "APAC Japan",
        timezone: "Asia/Tokyo",
        locale: "ja-JP",
        languages: &["ja-JP", "ja", "en-US", "en"],
        lat: 35.6762,
        lon: 139.6503,
        country: "JP",
    },
    GeoRegion {
        name: "APAC India",
        timezone: "Asia/Kolkata",
        locale: "en-IN",
        languages: &["en-IN", "en", "hi"],
        lat: 28.6139,
        lon: 77.2090,
        country: "IN",
    },
    GeoRegion {
        name: "APAC Australia",
        timezone: "Australia/Sydney",
        locale: "en-AU",
        languages: &["en-AU", "en"],
        lat: -33.8688,
        lon: 151.2093,
        country: "AU",
    },
    GeoRegion {
        name: "North America Canada",
        timezone: "America/Toronto",
        locale: "en-CA",
        languages: &["en-CA", "en", "fr"],
        lat: 43.6532,
        lon: -79.3832,
        country: "CA",
    },
];

/// Look up a built-in region by its human-readable name.
#[must_use]
pub fn geo_region_by_name(name: &str) -> Option<&'static GeoRegion> {
    GEO_REGIONS
        .iter()
        .find(|r| r.name.eq_ignore_ascii_case(name))
}

/// Look up a built-in region by timezone, falling back to a region whose
/// timezone starts with the same IANA area (e.g. `America/`).
#[must_use]
pub fn geo_region_by_timezone(timezone: &str) -> Option<&'static GeoRegion> {
    GEO_REGIONS
        .iter()
        .find(|r| r.timezone == timezone)
        .or_else(|| {
            let area = timezone.split('/').next().unwrap_or("");
            GEO_REGIONS.iter().find(|r| r.timezone.starts_with(area))
        })
}

#[cfg(feature = "tier-b-toml")]
mod loader_impl {
    use super::GeoRegion;
    use crate::fingerprint::geo_coherence::{identity_geo_coherence, GeoCoherence};
    use std::path::Path;

    /// Upper bound on a single Tier-B geo-region TOML (16 KiB).
    const MAX_GEO_REGION_TOML_BYTES: u64 = 16 * 1024;

    /// Error loading a Tier-B geo-region preset. Fail-closed (Law 10).
    #[derive(Debug)]
    pub enum GeoRegionLoadError {
        /// File could not be read.
        Read(String),
        /// File exceeded the size cap.
        TooLarge {
            /// Offending path.
            path: String,
            /// Actual size.
            bytes: u64,
        },
        /// TOML did not parse.
        Parse(String),
        /// A field was missing or invalid.
        Invalid {
            /// Path of the offending file.
            path: String,
            /// Why it was rejected.
            reason: String,
        },
        /// The preset failed the geo-coherence gate.
        Incoherent {
            /// Path of the offending file.
            path: String,
            /// Verdict from the coherence check.
            verdict: GeoCoherence,
        },
    }

    impl std::fmt::Display for GeoRegionLoadError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Read(e) => write!(f, "tier-b geo-region: read failed: {e}"),
                Self::TooLarge { path, bytes } => write!(
                    f,
                    "tier-b geo-region: {path} is {bytes} bytes, over the {MAX_GEO_REGION_TOML_BYTES}-byte cap"
                ),
                Self::Parse(e) => write!(f, "tier-b geo-region: TOML parse failed: {e}"),
                Self::Invalid { path, reason } => {
                    write!(f, "tier-b geo-region: {path} invalid: {reason}")
                }
                Self::Incoherent { path, verdict } => {
                    write!(f, "tier-b geo-region: {path} is not coherent: {verdict:?}")
                }
            }
        }
    }

    impl std::error::Error for GeoRegionLoadError {}

    #[derive(serde::Deserialize)]
    struct GeoRegionDoc {
        name: String,
        timezone: String,
        locale: String,
        languages: Vec<String>,
        lat: f64,
        lon: f64,
        country: String,
    }

    fn leak_string(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    fn leak_str_slice(v: Vec<String>) -> &'static [&'static str] {
        let leaked: Vec<&'static str> = v.into_iter().map(|s| leak_string(s)).collect();
        Box::leak(leaked.into_boxed_slice())
    }

    /// Load a single Tier-B geo-region preset from TOML and prove it is
    /// internally geo-coherent before returning it.
    ///
    /// # Errors
    /// [`GeoRegionLoadError`] on read failure, oversize, parse failure, a missing
    /// field, or a coherence failure.
    pub fn load_geo_region_from_toml(path: &Path) -> Result<GeoRegion, GeoRegionLoadError> {
        let meta = std::fs::metadata(path)
            .map_err(|e| GeoRegionLoadError::Read(format!("{}: {e}", path.display())))?;
        if meta.len() > MAX_GEO_REGION_TOML_BYTES {
            return Err(GeoRegionLoadError::TooLarge {
                path: path.display().to_string(),
                bytes: meta.len(),
            });
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| GeoRegionLoadError::Read(format!("{}: {e}", path.display())))?;
        let doc: GeoRegionDoc =
            toml::from_str(&raw).map_err(|e| GeoRegionLoadError::Parse(e.to_string()))?;

        let name = doc.name.trim();
        let timezone = doc.timezone.trim();
        let locale = doc.locale.trim();
        let country = doc.country.trim();
        let invalid = |reason: &str| GeoRegionLoadError::Invalid {
            path: path.display().to_string(),
            reason: reason.to_string(),
        };

        if name.is_empty() {
            return Err(invalid("empty name"));
        }
        if timezone.is_empty() {
            return Err(invalid("empty timezone"));
        }
        if locale.is_empty() {
            return Err(invalid("empty locale"));
        }
        if country.len() != 2 || !country.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(invalid(&format!(
                "country `{country}` is not a 2-letter ISO-3166 code"
            )));
        }
        if doc.languages.is_empty() {
            return Err(invalid("languages must not be empty"));
        }

        let region = GeoRegion {
            name: leak_string(name.to_string()),
            timezone: leak_string(timezone.to_string()),
            locale: leak_string(locale.to_string()),
            languages: leak_str_slice(
                doc.languages
                    .into_iter()
                    .map(|s| s.trim().to_string())
                    .collect(),
            ),
            lat: doc.lat,
            lon: doc.lon,
            country: leak_string(country.to_ascii_uppercase()),
        };

        // Prove the preset is coherent before we let any persona use it.
        let probe_identity = crate::fingerprint::identity::NavigatorProfile {
            stealth_profile_name: String::new(),
            hardware_index: 0,
            user_agent: String::new(),
            platform: String::new(),
            vendor: String::new(),
            screen_width: 1920,
            screen_height: 1080,
            color_depth: 24,
            device_memory: 8,
            hardware_concurrency: 4,
            timezone: region.timezone.to_string(),
            locale: region.locale.to_string(),
            languages: region.languages.iter().map(|s| s.to_string()).collect(),
            latitude: region.lat,
            longitude: region.lon,
            webgl_vendor: String::new(),
            webgl_renderer: String::new(),
            canvas_seed: 0.0,
            do_not_track: None,
            country: region.country.to_string(),
        };
        match identity_geo_coherence(&probe_identity) {
            GeoCoherence::Coherent => Ok(region),
            verdict => Err(GeoRegionLoadError::Incoherent {
                path: path.display().to_string(),
                verdict,
            }),
        }
    }

    /// Load every `*.toml` file in a Tier-B geo-region directory. The first
    /// malformed or incoherent file fails the whole load.
    pub fn load_geo_region_directory(path: &Path) -> Result<Vec<GeoRegion>, GeoRegionLoadError> {
        let mut files: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| GeoRegionLoadError::Read(format!("{}: {e}", path.display())))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("toml"))
            .collect();
        files.sort();

        let mut out = Vec::with_capacity(files.len());
        for file in files {
            out.push(load_geo_region_from_toml(&file)?);
        }
        Ok(out)
    }
}

#[cfg(feature = "tier-b-toml")]
pub use loader_impl::{load_geo_region_directory, load_geo_region_from_toml, GeoRegionLoadError};

#[cfg(test)]
#[path = "geo_region/tests.rs"]
mod tests;
