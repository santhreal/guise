//! Tier-B audio device persona library (G098).
//!
//! Real browsers expose audio input/output device labels via
//! `navigator.mediaDevices.enumerateDevices()`. The host's actual devices are a
//! fingerprint, so a persona should present a coherent, platform-typical set.
//! This loader lets an operator extend the built-in device sets from TOML
//! drop-ins without recompiling.
//!
//! A malformed file fails closed (Law 10): the first bad entry rejects the whole
//! load, no device is ever silently skipped, because a skipped entry would
//! create a coverage hole in the audio-device fingerprint.

/// One audio device entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioDevicePersona {
    /// MediaDeviceKind: `"audioinput"` or `"audiooutput"`.
    pub kind: &'static str,
    /// Human-readable device label.
    pub label: &'static str,
}

impl AudioDevicePersona {
    /// Whether this is an audio input device.
    #[must_use]
    pub fn is_input(&self) -> bool {
        self.kind == "audioinput"
    }

    /// Whether this is an audio output device.
    #[must_use]
    pub fn is_output(&self) -> bool {
        self.kind == "audiooutput"
    }
}

#[cfg(feature = "tier-b-toml")]
mod loader_impl {
    use super::AudioDevicePersona;
    use std::path::Path;

    /// Upper bound on a Tier-B audio-device TOML (64 KiB).
    const MAX_AUDIO_DEVICE_TOML_BYTES: u64 = 64 * 1024;

    /// Error loading a Tier-B audio device persona library. Every variant is a
    /// loud, fail-closed outcome.
    #[derive(Debug)]
    pub enum AudioDeviceLoadError {
        /// The file could not be read.
        Read(String),
        /// The file exceeds [`MAX_AUDIO_DEVICE_TOML_BYTES`].
        TooLarge {
            /// The offending path.
            path: String,
            /// Actual size in bytes.
            bytes: u64,
        },
        /// The TOML did not parse.
        Parse(String),
        /// A device entry was malformed (carries index + reason).
        Invalid {
            /// One-based entry index in the file.
            index: usize,
            /// Why it was rejected.
            reason: String,
        },
    }

    impl std::fmt::Display for AudioDeviceLoadError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Read(e) => write!(f, "tier-b audio-device: read failed: {e}"),
                Self::TooLarge { path, bytes } => write!(
                    f,
                    "tier-b audio-device: {path} is {bytes} bytes, over the {MAX_AUDIO_DEVICE_TOML_BYTES}-byte cap"
                ),
                Self::Parse(e) => write!(f, "tier-b audio-device: TOML parse failed: {e}"),
                Self::Invalid { index, reason } => {
                    write!(f, "tier-b audio-device: entry #{index} invalid: {reason}")
                }
            }
        }
    }

    impl std::error::Error for AudioDeviceLoadError {}

    #[derive(serde::Deserialize)]
    struct AudioDeviceDoc {
        kind: String,
        label: String,
    }

    #[derive(serde::Deserialize)]
    struct AudioDevicesDoc {
        /// `[[audio_device]]` array-of-tables; empty/absent is a successful load
        /// of zero devices, not an error.
        #[serde(default)]
        audio_device: Vec<AudioDeviceDoc>,
    }

    fn valid_kind(kind: &str) -> bool {
        matches!(kind, "audioinput" | "audiooutput")
    }

    /// Load + validate Tier-B audio device personas from a TOML file.
    ///
    /// Every entry is validated: kind must be `audioinput` or `audiooutput`, and
    /// label must be non-empty. The first malformed entry fails the whole load
    /// (fail-closed).
    ///
    /// # Errors
    /// [`AudioDeviceLoadError`] on read failure, oversize, parse failure, or a
    /// malformed device entry.
    pub fn load_audio_devices_from_toml(
        path: &Path,
    ) -> Result<Vec<AudioDevicePersona>, AudioDeviceLoadError> {
        let meta = std::fs::metadata(path)
            .map_err(|e| AudioDeviceLoadError::Read(format!("{}: {e}", path.display())))?;
        if meta.len() > MAX_AUDIO_DEVICE_TOML_BYTES {
            return Err(AudioDeviceLoadError::TooLarge {
                path: path.display().to_string(),
                bytes: meta.len(),
            });
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| AudioDeviceLoadError::Read(format!("{}: {e}", path.display())))?;
        let doc: AudioDevicesDoc =
            toml::from_str(&raw).map_err(|e| AudioDeviceLoadError::Parse(e.to_string()))?;

        let mut out = Vec::with_capacity(doc.audio_device.len());
        for (idx, d) in doc.audio_device.into_iter().enumerate() {
            let index = idx + 1;
            let invalid = |reason: &str| AudioDeviceLoadError::Invalid {
                index,
                reason: reason.to_string(),
            };

            let kind = d.kind.trim();
            let label = d.label.trim();
            if !valid_kind(kind) {
                return Err(invalid(&format!(
                    "kind `{kind}` is not audioinput/audiooutput"
                )));
            }
            if label.is_empty() {
                return Err(invalid("empty label"));
            }

            out.push(AudioDevicePersona {
                kind: Box::leak(kind.to_string().into_boxed_str()),
                label: Box::leak(label.to_string().into_boxed_str()),
            });
        }
        Ok(out)
    }

    /// Load every `*.toml` file in a Tier-B audio-device directory, merging them
    /// into one pooled library. Files are processed in lexicographic order; the
    /// first malformed file fails the whole load.
    pub fn load_audio_device_directory(
        path: &Path,
    ) -> Result<Vec<AudioDevicePersona>, AudioDeviceLoadError> {
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| AudioDeviceLoadError::Read(format!("{}: {e}", path.display())))?
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
            out.extend(load_audio_devices_from_toml(&path)?);
        }
        Ok(out)
    }
}

#[cfg(feature = "tier-b-toml")]
pub use loader_impl::{
    load_audio_device_directory, load_audio_devices_from_toml, AudioDeviceLoadError,
};

#[cfg(all(test, feature = "tier-b-toml"))]
#[path = "audio_device_tier_b/tests.rs"]
mod tests;
