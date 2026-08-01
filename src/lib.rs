//! `guise`: canonical stealth substrate for the Santh fleet.
//!
//! `guise` consolidates the fleet's previously-duplicated stealth
//! implementations (captchaforge, archived golemn-browser, wafrift, see
//! `MASTER_PLAN/02_stealth.md`) into one lib with four orthogonal primitives:
//! browser-fingerprint profiles, human-behavior timing, TLS-profile re-exports,
//! and a runtime stealth-probe that verifies the disguise actually defeats
//! detection at runtime (not just that the override is present in source).
//!
//! # Vocabulary (one naming convention)
//!
//! - `StealthProfile` is the **canonical selector**: the one enum naming a
//!   coherent (browser, OS, GPU) identity. Everything derives from it.
//! - `profile_facts(StealthProfile) -> ProfileFacts` is the **source data**.
//! - A `<Domain>Profile` is a pure, derived *projection* of that data for one
//!   domain (e.g. `HeaderProfile` (HTTP headers), and the TLS / geo facets).
//!   There is exactly **one** type per projection; no per-module duplicates.
//! - **Applied / runtime** instances are named for what they are, never `*Profile`
//!   (e.g. `http::RequestHeaders` (a materialized header set)).
//! - **Home-rule:** `fingerprint/` owns fingerprint DATA; `http/` and `cdp/` APPLY it.
//!
//! # Features
//!
//! | Feature | Enables |
//! |---------|---------|
//! | `fingerprint` (default) | [`fingerprint`] profile bundles + JS overrides |
//! | `human` (default) | [`human`] keystroke / mouse / behavioral-grammar timing |
//! | `http-headers` (default via `http`) | [`http`] browser header templates without TLS deps |
//! | `http` (default) | [`http`] browser headers + TLS profile re-exports |
//! | `pacing` (default) | [`pacing`] jitter + retry backoff policies |
//! | `rotation` (default) | [`rotation`] profile cycling + config-name resolution |
//! | `config` (default) | [`config`] Tier-A defaults→TOML→CLI configuration |
//! | `tls-impersonate` | [`http::StealthClient`] (wreq / BoringSSL) |
//! | `browser` | [`browser`] BiDi stealth application, [`human`] timing, and the [`probe`] runtime self-test |
//! | `tier-b-toml` | [`ProfileBundle::from_toml`] community profiles |
//!
//! # Safe defaults
//!
//! - **Input size:** No cap enforced. All inputs are in-memory Rust values
//!   (`&str`, typed structs). The only I/O is `ProfileBundle::from_toml` (the
//!   `tier-b-toml` feature), which reads a TOML file entirely into a `String`
//!   via `std::fs::read_to_string` - the limit is the OS file-size limit; no
//!   internal byte cap is applied. All other APIs operate on already-loaded
//!   in-memory data with no size constraint.
//! - **Recursion depth:** No recursive algorithms are present in this crate.
//!   All iteration is flat (loops over slices and hash-map look-ups); stack
//!   depth is bounded by the call chain depth alone.
//! - **Outbound network:** None. This crate emits no outbound connections of
//!   any kind. The `http` feature re-exports type definitions from `scanclient`
//!   but does not initiate requests; the optional `tls-impersonate` feature's
//!   `StealthClient` is owned by `scanclient` and is only forwarded here.
//! - **Process spawning:** The `browser` feature delegates process spawning to
//!   the `runtime-foxdriver` crate (Firefox BiDi launch).  `guise` itself does
//!   not call `std::process::Command` directly.
//! - **Filesystem writes:** None. The only filesystem access is the read in
//!   `ProfileBundle::from_toml` (`tier-b-toml` feature). No file is written,
//!   created, or truncated anywhere in this crate.
//! - **Credential exposure:** None. This crate holds no credentials, API keys,
//!   or secrets and does not log, serialize, or transmit caller-supplied data
//!   outside the process. Profile bundles contain only synthetic browser
//!   fingerprint constants (UA strings, screen sizes, WebGL strings).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

#[cfg(feature = "browser")]
pub mod browser;
pub mod choice;
#[cfg(feature = "config")]
pub mod config;
#[cfg(feature = "fingerprint")]
pub mod fingerprint;
#[cfg(any(feature = "http", feature = "http-headers"))]
pub mod http;
#[cfg(feature = "human")]
pub mod human;
#[cfg(feature = "pacing")]
pub mod pacing;
#[cfg(all(feature = "fingerprint", feature = "rotation"))]
pub mod persona_pool;
#[cfg(feature = "browser")]
pub mod probe;
#[cfg(feature = "rotation")]
pub mod rotation;
mod sampling;

#[cfg(feature = "fingerprint")]
pub use fingerprint::{ProfileBundle, ProfileError, StealthProfile, DEFAULT_STEALTH_PROFILE};

#[cfg(feature = "human")]
pub use human::{Keystroke, TypingPlan};

#[cfg(feature = "human")]
pub use human::keystroke::{bigram_gap, hold_envelope, plan_keystrokes, qwerty_neighbour};

#[cfg(feature = "fingerprint")]
pub use fingerprint::{profile_js, profile_to_overrides, ProfileOverrides};

#[cfg(feature = "browser")]
pub use browser::{
    apply_default_stealth_profile, apply_session_age, apply_stealth, apply_stealth_profile,
    automation_prefs, build_user_js, enforce_persona_launch_coherence, generate_session_age,
    launch_default_profiled_firefox, launch_profiled_firefox, SessionAgeSeed,
};

// Runtime stealth self-test, surfaced at the crate root so a consumer can probe
// a live page against the correct browser family without reaching into the
// module: `guise::run_probe_for(&page, guise::UserAgentBrowser::Firefox)`.
#[cfg(feature = "browser")]
pub use probe::{
    audit_page as audit_stealth, audit_page_for as audit_stealth_for, probes_for, run as run_probe,
    run_for as run_probe_for, DriftReport, ProbeOutcome, UserAgentBrowser,
};
