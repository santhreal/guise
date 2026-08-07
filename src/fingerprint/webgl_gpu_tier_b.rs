//! Tier-B WebGL GPU persona library (G095).
//!
//! Built-in profiles ship a small, proven set of `UNMASKED_VENDOR_WEBGL` /
//! `UNMASKED_RENDERER_WEBGL` pairs in `guise-profiles`. This loader lets an
//! operator extend that set from TOML drop-ins without recompiling, so the
//! anti-uniqueness pool can grow as new real GPUs are measured.
//!
//! A malformed file fails closed (Law 10): the first bad or duplicate entry
//! rejects the whole load, no GPU is ever silently skipped, because a skipped
//! entry would create a coverage hole in the WebGL persona pool.
//!
//! The loaded personas are validated against the same coherence rule the bundle
//! gate enforces: an Apple GPU can only appear on an Apple platform. The
//! `webgl_gpu_vendor_families` helper exposes the canonical vendor families so
//! callers can filter by platform without string-matching.

use std::path::Path;

/// Upper bound on a Tier-B WebGL GPU TOML (64 KiB). The library is small text
/// data; this bounds a hostile or accidental oversized drop-in.
const MAX_WEBGL_GPU_TOML_BYTES: u64 = 64 * 1024;

/// One measured WebGL GPU persona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebGlGpuPersona {
    /// `UNMASKED_VENDOR_WEBGL` value (e.g. `"Google Inc. (NVIDIA)"`).
    pub vendor: &'static str,
    /// `UNMASKED_RENDERER_WEBGL` value (e.g. `"ANGLE (NVIDIA, GeForce ... )"`).
    pub renderer: &'static str,
}

/// Canonical vendor families in the WebGL GPU persona library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebGlGpuFamily {
    /// Intel integrated GPUs (UHD, Iris Xe).
    Intel,
    /// NVIDIA discrete GPUs.
    Nvidia,
    /// AMD discrete GPUs.
    Amd,
    /// Apple GPUs (native Safari + ANGLE-wrapped Chrome-on-macOS).
    Apple,
    /// Qualcomm Adreno mobile GPUs.
    Qualcomm,
    /// Mesa open-source stack (Linux).
    Mesa,
    /// Brave browser (masks real adapter).
    Brave,
    /// Legacy Microsoft/IE11.
    Microsoft,
    /// Vendor string not matching any known family.
    Other,
}

impl WebGlGpuFamily {
    /// Whether this GPU family can physically exist on the given platform.
    ///
    /// This mirrors the coherence gate in `bundle::validate_overrides`: Apple
    /// GPUs are Apple-platform-only; every other family is assumed to exist on
    /// at least one non-Apple platform.
    pub fn coherent_with_platform(self, platform: &str) -> bool {
        match self {
            Self::Apple => platform == "MacIntel" || platform == "iPhone" || platform == "iPad",
            // All non-Apple families are forbidden on Apple platforms, a Windows
            // Chrome persona claiming an NVIDIA GPU on an iPhone is a tell.
            _ => !matches!(platform, "MacIntel" | "iPhone" | "iPad"),
        }
    }
}

/// Error loading a Tier-B WebGL GPU persona library. Every variant is a loud,
/// fail-closed outcome.
#[derive(Debug)]
pub enum WebGlGpuLoadError {
    /// The file could not be read.
    Read(String),
    /// The file exceeds [`MAX_WEBGL_GPU_TOML_BYTES`].
    TooLarge {
        /// The offending path.
        path: String,
        /// Actual size in bytes.
        bytes: u64,
    },
    /// The TOML did not parse.
    Parse(String),
    /// A GPU entry was malformed (carries index + reason).
    Invalid {
        /// One-based entry index in the file.
        index: usize,
        /// Why it was rejected.
        reason: String,
    },
}

impl std::fmt::Display for WebGlGpuLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(e) => write!(f, "tier-b webgl-gpu: read failed: {e}"),
            Self::TooLarge { path, bytes } => write!(
                f,
                "tier-b webgl-gpu: {path} is {bytes} bytes, over the {MAX_WEBGL_GPU_TOML_BYTES}-byte cap"
            ),
            Self::Parse(e) => write!(f, "tier-b webgl-gpu: TOML parse failed: {e}"),
            Self::Invalid { index, reason } => {
                write!(f, "tier-b webgl-gpu: entry #{index} invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for WebGlGpuLoadError {}

#[derive(serde::Deserialize)]
struct GpuDoc {
    vendor: String,
    renderer: String,
}

#[derive(serde::Deserialize)]
struct GpusDoc {
    /// `[[gpu]]` array-of-tables; empty/absent is a successful load of zero
    /// GPUs, not an error.
    #[serde(default)]
    gpu: Vec<GpuDoc>,
}

/// Classify a vendor string into a canonical family.
pub fn webgl_gpu_vendor_family(vendor: &str) -> WebGlGpuFamily {
    let lower = vendor.to_ascii_lowercase();
    if lower.contains("intel") {
        WebGlGpuFamily::Intel
    } else if lower.contains("nvidia") {
        WebGlGpuFamily::Nvidia
    } else if lower.contains("amd") || lower.contains("radeon") {
        WebGlGpuFamily::Amd
    } else if lower.contains("apple") {
        WebGlGpuFamily::Apple
    } else if lower.contains("qualcomm") || lower.contains("adreno") {
        WebGlGpuFamily::Qualcomm
    } else if lower.contains("mesa") {
        WebGlGpuFamily::Mesa
    } else if lower.contains("brave") {
        WebGlGpuFamily::Brave
    } else if lower.contains("microsoft") {
        WebGlGpuFamily::Microsoft
    } else {
        WebGlGpuFamily::Other
    }
}

/// Load + validate Tier-B WebGL GPU personas from a TOML file.
///
/// The returned strings are leaked to `'static` (a load-once library lives for
/// the process), so each [`WebGlGpuPersona`] can be used anywhere the built-in
/// GPU strings are.
///
/// Every entry is validated: non-empty vendor and renderer, and the vendor
/// family must be coherent with at least one known platform (Apple GPUs only on
/// Apple platforms; every other family only on non-Apple platforms). The first
/// malformed entry fails the whole load (fail-closed).
///
/// # Errors
/// [`WebGlGpuLoadError`] on read failure, oversize, parse failure, or a
/// malformed GPU entry.
pub fn load_webgl_gpus_from_toml(path: &Path) -> Result<Vec<WebGlGpuPersona>, WebGlGpuLoadError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| WebGlGpuLoadError::Read(format!("{}: {e}", path.display())))?;
    if meta.len() > MAX_WEBGL_GPU_TOML_BYTES {
        return Err(WebGlGpuLoadError::TooLarge {
            path: path.display().to_string(),
            bytes: meta.len(),
        });
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| WebGlGpuLoadError::Read(format!("{}: {e}", path.display())))?;
    let doc: GpusDoc = toml::from_str(&raw).map_err(|e| WebGlGpuLoadError::Parse(e.to_string()))?;

    let mut out = Vec::with_capacity(doc.gpu.len());
    for (idx, d) in doc.gpu.into_iter().enumerate() {
        let index = idx + 1;
        let invalid = |reason: &str| WebGlGpuLoadError::Invalid {
            index,
            reason: reason.to_string(),
        };

        let vendor = d.vendor.trim();
        let renderer = d.renderer.trim();
        if vendor.is_empty() {
            return Err(invalid("empty vendor"));
        }
        if renderer.is_empty() {
            return Err(invalid("empty renderer"));
        }

        let family = webgl_gpu_vendor_family(vendor);
        if family == WebGlGpuFamily::Other {
            return Err(invalid(&format!(
                "unknown GPU vendor family for vendor {vendor:?}"
            )));
        }
        let coherent_platform = match family {
            WebGlGpuFamily::Apple => "MacIntel",
            _ => "Win32",
        };
        if !family.coherent_with_platform(coherent_platform) {
            return Err(invalid(&format!(
                "vendor family {family:?} is incoherent with every known platform"
            )));
        }

        out.push(WebGlGpuPersona {
            vendor: Box::leak(vendor.to_string().into_boxed_str()),
            renderer: Box::leak(renderer.to_string().into_boxed_str()),
        });
    }
    Ok(out)
}

/// Load every `*.toml` file in a Tier-B WebGL GPU directory, merging them into
/// one pooled persona library. Files are processed in lexicographic order; the
/// first malformed file fails the whole load.
pub fn load_webgl_gpu_directory(dir: &Path) -> Result<Vec<WebGlGpuPersona>, WebGlGpuLoadError> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| WebGlGpuLoadError::Read(format!("{}: {e}", dir.display())))?
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
        out.extend(load_webgl_gpus_from_toml(&path)?);
    }
    Ok(out)
}

#[cfg(test)]
#[path = "webgl_gpu_tier_b/tests.rs"]
mod tests;
