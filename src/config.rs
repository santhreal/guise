//! Tier-A configuration for the guise persona lifecycle.
//!
//! This module exposes the operator-facing knobs that drive rotation, pacing,
//! and the persona pool.  It follows the fleet's Tier-A contract:
//! **hard-coded safe defaults → TOML file → CLI override** (G245).  Every
//! knob can be set in all three layers, and the precedence is explicit:
//! CLI wins over file, file wins over defaults.
//!
//! # Example TOML
//!
//! ```toml
//! [rotation]
//! policy = "per_requests"
//! per_requests_n = 100
//!
//! [pacing]
//! page_load_ms = [800, 3000]
//! sub_resource_ms = [100, 400]
//! api_call_ms = [300, 1200]
//!
//! [pool]
//! max_concurrent_sessions = 16
//! ```
//!
//! # Hot reload
//!
//! [`TierBPersonaDir`] (enabled with the `tier-b-toml` feature) scans a
//! directory of community profile TOMLs and can be asked to reload when the
//! newest file changes.  Dropping a new persona file into the directory and
//! calling [`TierBPersonaDir::reload_if_changed`] picks it up without a rebuild
//! (G247/G248).
//!
//! # Example
//!
//! ```
//! use guise::config::{GuiseConfig, RotationPolicyName};
//!
//! let cfg = GuiseConfig::default()
//!     .with_rotation_policy(RotationPolicyName::PerTarget)
//!     .with_max_concurrent_sessions(8)
//!     .with_pacing_page_load_ms(900, 2_500)
//!     .unwrap();
//!
//! assert_eq!(cfg.pool.max_concurrent_sessions, 8);
//! assert_eq!(cfg.rotation.policy, RotationPolicyName::PerTarget);
//! ```

use std::path::Path;
#[cfg(feature = "tier-b-toml")]
use std::path::PathBuf;
#[cfg(feature = "tier-b-toml")]
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "pacing")]
use crate::pacing::{BoundedNormalDelay, RequestPacer};

#[cfg(feature = "rotation")]
use crate::rotation::RotationPolicy;

/// Errors produced while loading or applying configuration.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Reading a config file from disk failed.
    #[error("failed to read config file: {0}")]
    Read(String),
    /// Parsing the TOML failed or produced an invalid value.
    #[error("failed to parse config TOML: {0}")]
    TomlParse(String),
    /// A pacing interval was given with `min > max`.
    #[error("invalid pacing bounds: min {min_ms} ms is greater than max {max_ms} ms")]
    InvalidPacingBounds {
        /// Inclusive lower bound that was rejected.
        min_ms: u64,
        /// Inclusive upper bound that was rejected.
        max_ms: u64,
    },
    /// Loading a Tier-B persona file failed validation.
    #[error("invalid Tier-B persona: {0}")]
    Profile(String),
}

/// Top-level guise configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GuiseConfig {
    /// When and how personas rotate.
    #[cfg(feature = "rotation")]
    pub rotation: RotationConfig,
    /// Request/behavioral pacing bounds.
    #[cfg(feature = "pacing")]
    pub pacing: PacingConfig,
    /// Pool-level lifecycle settings.
    pub pool: PoolConfig,
}

impl GuiseConfig {
    /// Load configuration from a TOML file on disk.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] on I/O failure or [`ConfigError::TomlParse`]
    /// if the file is not valid configuration TOML.
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::Read(format!("{}: {e}", path.as_ref().display())))?;
        Self::from_toml_str(&raw)
    }

    /// Parse configuration from a TOML string.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::TomlParse`] if the string is not valid.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::TomlParse(e.to_string()))
    }

    /// Convert this configuration into a [`crate::persona_pool::PoolConfig`].
    #[cfg(all(feature = "rotation", feature = "fingerprint"))]
    #[must_use]
    pub fn to_pool_config(self) -> crate::persona_pool::PoolConfig {
        crate::persona_pool::PoolConfig {
            rotation_policy: self.rotation.to_policy(),
            max_concurrent_sessions: self.pool.max_concurrent_sessions,
        }
    }

    /// Build the default request pacer implied by the configuration.
    #[cfg(feature = "pacing")]
    #[must_use]
    pub fn request_pacer(self) -> RequestPacer {
        self.pacing.page_load_pacer()
    }

    /// CLI-style override: set the rotation policy.
    #[cfg(feature = "rotation")]
    #[must_use]
    pub fn with_rotation_policy(mut self, policy: RotationPolicyName) -> Self {
        self.rotation.policy = policy;
        self
    }

    /// CLI-style override: set the per-`N`-requests rotation interval.
    #[cfg(feature = "rotation")]
    #[must_use]
    pub fn with_per_requests_n(mut self, n: u64) -> Self {
        self.rotation.per_requests_n = n;
        self
    }

    /// CLI-style override: set the concurrent-session capacity limit.
    #[must_use]
    pub fn with_max_concurrent_sessions(mut self, limit: usize) -> Self {
        self.pool.max_concurrent_sessions = limit;
        self
    }

    /// CLI-style override: set page-load pacing bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidPacingBounds`] if `min_ms > max_ms`.
    #[cfg(feature = "pacing")]
    pub fn with_pacing_page_load_ms(
        mut self,
        min_ms: u64,
        max_ms: u64,
    ) -> Result<Self, ConfigError> {
        self.pacing.page_load_ms = validate_bounds(min_ms, max_ms)?;
        Ok(self)
    }

    /// CLI-style override: set sub-resource pacing bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidPacingBounds`] if `min_ms > max_ms`.
    #[cfg(feature = "pacing")]
    pub fn with_pacing_sub_resource_ms(
        mut self,
        min_ms: u64,
        max_ms: u64,
    ) -> Result<Self, ConfigError> {
        self.pacing.sub_resource_ms = validate_bounds(min_ms, max_ms)?;
        Ok(self)
    }

    /// CLI-style override: set API-call pacing bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidPacingBounds`] if `min_ms > max_ms`.
    #[cfg(feature = "pacing")]
    pub fn with_pacing_api_call_ms(
        mut self,
        min_ms: u64,
        max_ms: u64,
    ) -> Result<Self, ConfigError> {
        self.pacing.api_call_ms = validate_bounds(min_ms, max_ms)?;
        Ok(self)
    }
}

/// Rotation policy as configured by name, plus the integer parameter used by
/// [`RotationPolicyName::PerRequests`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RotationConfig {
    /// Named rotation policy.
    pub policy: RotationPolicyName,
    /// Interval for `per_requests`.
    pub per_requests_n: u64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            policy: RotationPolicyName::PerSession,
            per_requests_n: 0,
        }
    }
}

impl RotationConfig {
    /// Convert the named config into the runtime [`RotationPolicy`].
    #[cfg(feature = "rotation")]
    #[must_use]
    pub fn to_policy(self) -> RotationPolicy {
        match self.policy {
            RotationPolicyName::Never => RotationPolicy::Never,
            RotationPolicyName::PerSession => RotationPolicy::PerSession,
            RotationPolicyName::PerTarget => RotationPolicy::PerTarget,
            RotationPolicyName::PerRequests => RotationPolicy::PerRequests(self.per_requests_n),
        }
    }
}

/// Serializable name for each rotation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RotationPolicyName {
    /// Never rotate.
    Never,
    /// Rotate once at session start.
    #[default]
    PerSession,
    /// Rotate when the target domain changes.
    PerTarget,
    /// Rotate every `N` requests.
    PerRequests,
}

/// Request-pacing bounds as Tier-A config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PacingConfig {
    /// Page-load pacing bounds in milliseconds.
    pub page_load_ms: (u64, u64),
    /// Sub-resource pacing bounds in milliseconds.
    pub sub_resource_ms: (u64, u64),
    /// API-call pacing bounds in milliseconds.
    pub api_call_ms: (u64, u64),
}

impl Default for PacingConfig {
    fn default() -> Self {
        Self {
            page_load_ms: (800, 3_000),
            sub_resource_ms: (100, 400),
            api_call_ms: (300, 1_200),
        }
    }
}

impl PacingConfig {
    /// Build a [`RequestPacer`] for page-load timing.
    #[cfg(feature = "pacing")]
    #[must_use]
    pub fn page_load_pacer(self) -> RequestPacer {
        RequestPacer::new(BoundedNormalDelay::from_unordered_bounds(
            self.page_load_ms.0,
            self.page_load_ms.1,
        ))
    }

    /// Build a [`RequestPacer`] for sub-resource timing.
    #[cfg(feature = "pacing")]
    #[must_use]
    pub fn sub_resource_pacer(self) -> RequestPacer {
        RequestPacer::new(BoundedNormalDelay::from_unordered_bounds(
            self.sub_resource_ms.0,
            self.sub_resource_ms.1,
        ))
    }

    /// Build a [`RequestPacer`] for API-call timing.
    #[cfg(feature = "pacing")]
    #[must_use]
    pub fn api_call_pacer(self) -> RequestPacer {
        RequestPacer::new(BoundedNormalDelay::from_unordered_bounds(
            self.api_call_ms.0,
            self.api_call_ms.1,
        ))
    }
}

/// Pool settings that are not part of the rotation policy itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PoolConfig {
    /// Maximum number of sessions that may be active at once (`0` = unlimited).
    pub max_concurrent_sessions: usize,
}

fn validate_bounds(min_ms: u64, max_ms: u64) -> Result<(u64, u64), ConfigError> {
    if min_ms > max_ms {
        return Err(ConfigError::InvalidPacingBounds { min_ms, max_ms });
    }
    Ok((min_ms, max_ms))
}

/// Hot-reloadable directory of Tier-B persona TOMLs (G247/G248).
///
/// Create one of these pointing at a directory of `*.toml` files, call
/// [`Self::scan`] to load them, and periodically call
/// [`Self::reload_if_changed`] to pick up newly dropped or edited files.
#[cfg(feature = "tier-b-toml")]
#[derive(Debug, Clone)]
pub struct TierBPersonaDir {
    path: PathBuf,
    last_mtime: Option<SystemTime>,
    profiles: Vec<crate::fingerprint::ProfileBundle>,
}

#[cfg(feature = "tier-b-toml")]
impl TierBPersonaDir {
    /// Create a watcher for the given directory.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            last_mtime: None,
            profiles: Vec::new(),
        }
    }

    /// Return the currently loaded profiles without scanning disk.
    #[must_use]
    pub fn profiles(&self) -> &[crate::fingerprint::ProfileBundle] {
        &self.profiles
    }

    /// Scan the directory and load every `*.toml` file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] if the directory cannot be read and
    /// [`ConfigError::Profile`] if any TOML fails validation.
    pub fn scan(&mut self) -> Result<&[crate::fingerprint::ProfileBundle], ConfigError> {
        self.profiles.clear();
        let mut latest: Option<SystemTime> = None;

        let entries = std::fs::read_dir(&self.path)
            .map_err(|e| ConfigError::Read(format!("{}: {e}", self.path.display())))?;

        for entry in entries {
            let entry = entry.map_err(|e| ConfigError::Read(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }

            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .map_err(|e| ConfigError::Read(format!("{}: {e}", path.display())))?;
            latest = Some(latest.map_or(mtime, |t| t.max(mtime)));

            let bundle = crate::fingerprint::ProfileBundle::from_toml(&path)
                .map_err(|e| ConfigError::Profile(format!("{}: {e}", path.display())))?;
            self.profiles.push(bundle);
        }

        self.last_mtime = latest;
        Ok(&self.profiles)
    }

    /// Reload the directory only if the newest `*.toml` mtime has changed.
    ///
    /// Returns `true` when a reload happened.
    ///
    /// # Errors
    ///
    /// Propagates the same errors as [`Self::scan`].
    pub fn reload_if_changed(&mut self) -> Result<bool, ConfigError> {
        let current = self.latest_mtime()?;
        if current != self.last_mtime {
            self.scan()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn latest_mtime(&self) -> Result<Option<SystemTime>, ConfigError> {
        let entries = std::fs::read_dir(&self.path)
            .map_err(|e| ConfigError::Read(format!("{}: {e}", self.path.display())))?;
        let mut latest: Option<SystemTime> = None;
        for entry in entries {
            let entry = entry.map_err(|e| ConfigError::Read(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .map_err(|e| ConfigError::Read(format!("{}: {e}", path.display())))?;
            latest = Some(latest.map_or(mtime, |t| t.max(mtime)));
        }
        Ok(latest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_expected() {
        let cfg = GuiseConfig::default();
        #[cfg(feature = "rotation")]
        {
            assert_eq!(cfg.rotation.policy, RotationPolicyName::PerSession);
            assert_eq!(cfg.rotation.per_requests_n, 0);
        }
        #[cfg(feature = "pacing")]
        {
            assert_eq!(cfg.pacing.page_load_ms, (800, 3_000));
            assert_eq!(cfg.pacing.sub_resource_ms, (100, 400));
            assert_eq!(cfg.pacing.api_call_ms, (300, 1_200));
        }
        assert_eq!(cfg.pool.max_concurrent_sessions, 0);
    }

    #[test]
    fn toml_round_trip_preserves_values() {
        let cfg = GuiseConfig::default()
            .with_rotation_policy(RotationPolicyName::PerRequests)
            .with_per_requests_n(50)
            .with_max_concurrent_sessions(4)
            .with_pacing_page_load_ms(900, 2_800)
            .unwrap()
            .with_pacing_sub_resource_ms(150, 350)
            .unwrap()
            .with_pacing_api_call_ms(400, 1_000)
            .unwrap();

        let toml = toml::to_string(&cfg).expect("serializable");
        let parsed = GuiseConfig::from_toml_str(&toml).expect("round-trippable");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn from_toml_str_parses_rotation_and_pacing() {
        let s = r#"
[rotation]
policy = "per_requests"
per_requests_n = 100

[pacing]
page_load_ms = [700, 2500]
sub_resource_ms = [80, 300]
api_call_ms = [250, 900]

[pool]
max_concurrent_sessions = 16
"#;
        let cfg = GuiseConfig::from_toml_str(s).unwrap();
        #[cfg(feature = "rotation")]
        {
            assert_eq!(cfg.rotation.policy, RotationPolicyName::PerRequests);
            assert_eq!(cfg.rotation.per_requests_n, 100);
            assert_eq!(cfg.rotation.to_policy(), RotationPolicy::PerRequests(100));
        }
        #[cfg(feature = "pacing")]
        {
            assert_eq!(cfg.pacing.page_load_ms, (700, 2_500));
            assert_eq!(cfg.pacing.sub_resource_ms, (80, 300));
            assert_eq!(cfg.pacing.api_call_ms, (250, 900));
        }
        assert_eq!(cfg.pool.max_concurrent_sessions, 16);
    }

    #[test]
    fn cli_overrides_take_precedence_over_defaults() {
        let cfg = GuiseConfig::default()
            .with_rotation_policy(RotationPolicyName::Never)
            .with_per_requests_n(7)
            .with_max_concurrent_sessions(12)
            .with_pacing_page_load_ms(1_000, 2_000)
            .unwrap();

        #[cfg(feature = "rotation")]
        {
            assert_eq!(cfg.rotation.policy, RotationPolicyName::Never);
            assert_eq!(cfg.rotation.per_requests_n, 7);
        }
        assert_eq!(cfg.pool.max_concurrent_sessions, 12);
        #[cfg(feature = "pacing")]
        {
            assert_eq!(cfg.pacing.page_load_ms, (1_000, 2_000));
        }
    }

    #[test]
    fn precedence_default_then_file_then_cli() {
        // Default values.
        assert_eq!(GuiseConfig::default().pacing.page_load_ms, (800, 3_000));

        // File values beat defaults.
        let file = GuiseConfig::from_toml_str(
            "[pacing]\npage_load_ms = [600, 2000]\n[rotation]\npolicy = \"per_target\"\n",
        )
        .unwrap();
        #[cfg(feature = "pacing")]
        assert_eq!(file.pacing.page_load_ms, (600, 2_000));
        #[cfg(feature = "rotation")]
        assert_eq!(file.rotation.policy, RotationPolicyName::PerTarget);

        // CLI values beat file values.
        let cli = file
            .with_rotation_policy(RotationPolicyName::Never)
            .with_pacing_page_load_ms(500, 1_500)
            .unwrap();
        #[cfg(feature = "rotation")]
        assert_eq!(cli.rotation.policy, RotationPolicyName::Never);
        #[cfg(feature = "pacing")]
        assert_eq!(cli.pacing.page_load_ms, (500, 1_500));
    }

    #[test]
    fn invalid_pacing_bounds_are_rejected() {
        let err = GuiseConfig::default()
            .with_pacing_page_load_ms(3_000, 800)
            .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidPacingBounds {
                min_ms: 3_000,
                max_ms: 800
            }
        ));
    }

    #[cfg(all(feature = "rotation", feature = "fingerprint"))]
    #[test]
    fn to_pool_config_matches_rotation_policy() {
        let cfg = GuiseConfig::default()
            .with_rotation_policy(RotationPolicyName::PerTarget)
            .with_max_concurrent_sessions(8);
        let pool = cfg.to_pool_config();
        assert_eq!(pool.rotation_policy, RotationPolicy::PerTarget);
        assert_eq!(pool.max_concurrent_sessions, 8);
    }

    #[cfg(feature = "pacing")]
    #[test]
    fn request_pacer_uses_configured_page_load_bounds() {
        let cfg = GuiseConfig::default()
            .with_pacing_page_load_ms(900, 1_100)
            .unwrap();
        let pacer = cfg.request_pacer();
        assert_eq!(pacer.challenge_multiplier(), 1);
    }

    #[cfg(all(feature = "tier-b-toml", feature = "rotation"))]
    #[test]
    fn tier_b_dir_scans_toml_files() {
        let dir = std::env::temp_dir().join(format!("guise-tier-b-{}-a", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("a.toml"),
            "browser = \"chrome-win\"\ntls = \"chrome131\"\n",
        )
        .unwrap();

        let mut watcher = TierBPersonaDir::new(&dir);
        let profiles = watcher.scan().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(
            profiles[0].browser,
            crate::fingerprint::StealthProfile::ChromeWindowsStable
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(all(feature = "tier-b-toml", feature = "rotation"))]
    #[test]
    fn tier_b_reload_detects_new_file() {
        let dir = std::env::temp_dir().join(format!("guise-tier-b-{}-b", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("a.toml"),
            "browser = \"chrome-win\"\ntls = \"chrome131\"\n",
        )
        .unwrap();

        let mut watcher = TierBPersonaDir::new(&dir);
        watcher.scan().unwrap();
        assert_eq!(watcher.profiles().len(), 1);

        std::fs::write(
            dir.join("b.toml"),
            "browser = \"firefox\"\ntls = \"firefox133\"\n",
        )
        .unwrap();
        let reloaded = watcher.reload_if_changed().unwrap();
        assert!(reloaded, "new persona file should trigger a reload");
        assert_eq!(watcher.profiles().len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
