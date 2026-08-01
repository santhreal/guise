//! The unified persona coherence gate (X007 / X045), one call asserting a
//! persona is coherent from the JS surface down to the wire, and the
//! host-vs-persona network-OS checks (does THIS host's TCP/IP stack betray the
//! persona's claimed OS). Composes the browser-half gate
//! ([`crate::fingerprint::bundle::validate_overrides`]) with the transport half
//! ([`super::transport::persona_transport_coherence`]).

use super::transport::{persona_transport_coherence, TransportIncoherence};
use crate::fingerprint::{
    os_network_coherence, os_network_stack, NetworkOsCoherence, StealthProfile, UserAgentPlatform,
};

/// Which HALF of the unified persona gate ([`persona_full_stack_coherence`])
/// rejected: the JS/browser surface or the wire/transport surface. The enclosing
/// type already conveys "incoherent"; each variant names the surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersonaIncoherence {
    /// The JS surface contradicts itself. UA ↔ `navigator.platform` ↔ WebGL GPU
    /// ↔ Client-Hint brands. Carries the browser-half gate's message.
    Browser(String),
    /// The wire surface contradicts itself. UA-OS ↔ TCP-OS, or the
    /// HTTP/2 ↔ header-order ↔ browser ↔ TLS families.
    Transport(TransportIncoherence),
}

impl std::fmt::Display for PersonaIncoherence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Browser(msg) => write!(f, "persona JS-surface incoherence: {msg}"),
            Self::Transport(t) => write!(f, "persona transport incoherence: {t:?}"),
        }
    }
}

impl std::error::Error for PersonaIncoherence {}

/// The unified persona coherence gate (X007 / X045): ONE call asserting a persona
/// is coherent from the JS surface all the way down to the wire
/// **UA-OS == TLS-OS == TCP-OS**, plus the browser half's
/// UA ↔ platform ↔ WebGL ↔ Client-Hint brands, plus HTTP/2 ↔ header-order ↔
/// browser-family agreement. Fails LOUD on ANY mismatch in either half.
///
/// This is the stack's "one coherent persona, JS-to-TCP" contract as a single
/// checkable function. Until now the two halves were separate gates a caller had
/// to remember to run both of, and which could drift apart:
/// [`crate::fingerprint::bundle::validate_overrides`] covered the browser/JS half
/// (and `ProfileBundle::validate_full_coherence` added browser↔TLS family), while
/// [`persona_transport_coherence`] covered the transport-OS half, neither covered
/// both. A caller wanting the full guarantee now makes one call.
#[must_use = "a coherence verdict that is ignored gates nothing"]
pub fn persona_full_stack_coherence(profile: StealthProfile) -> Result<(), PersonaIncoherence> {
    full_stack_coherence_of(profile, &crate::fingerprint::profile_to_overrides(&profile))
}

/// Testable seam for [`persona_full_stack_coherence`]: the browser half is checked
/// against the supplied `overrides` (so a test can break one JS axis and confirm
/// the unified gate SURFACES that failure rather than swallowing it. Law 10), the
/// transport half against `profile`. The public entry materialises `overrides`
/// from `profile`, so in production the two always describe the same persona.
pub(crate) fn full_stack_coherence_of(
    profile: StealthProfile,
    overrides: &crate::fingerprint::ProfileOverrides,
) -> Result<(), PersonaIncoherence> {
    crate::fingerprint::bundle::validate_overrides(overrides)
        .map_err(|e| PersonaIncoherence::Browser(e.to_string()))?;
    persona_transport_coherence(profile).map_err(PersonaIncoherence::Transport)?;
    Ok(())
}

/// OS family of the host this process runs on, in the persona OS taxonomy.
///
/// [`UserAgentPlatform::Unknown`] for platforms with no modeled network stack
/// (e.g. the BSDs), which keeps [`persona_host_network_coherence`] from
/// asserting a mismatch it cannot substantiate.
#[must_use]
pub fn host_platform() -> UserAgentPlatform {
    match std::env::consts::OS {
        "linux" => UserAgentPlatform::Linux,
        "macos" => UserAgentPlatform::MacOs,
        "windows" => UserAgentPlatform::Windows,
        "android" => UserAgentPlatform::Android,
        "ios" => UserAgentPlatform::Ios,
        _ => UserAgentPlatform::Unknown,
    }
}

/// Initial IP TTL this host's own TCP/IP stack stamps on outbound packets, the
/// TTL that egresses when no TCP-OS-rewriting proxy sits in front.
///
/// `None` when the host OS has no modeled stack.
#[must_use]
pub fn host_initial_ttl() -> Option<u8> {
    os_network_stack(host_platform()).map(|stack| stack.initial_ttl)
}

/// The initial IP TTL this host is *configured* to emit, read from the OS at
/// runtime rather than assumed from the OS family.
///
/// On Linux this reads `/proc/sys/net/ipv4/ip_default_ttl`, which catches a host
/// whose default TTL has been retuned away from the kernel default (e.g. already
/// set to 128 to mimic Windows), information the compile-time
/// [`host_initial_ttl`] cannot see. Returns `None` when the value cannot be read
/// or parsed (unsupported OS, missing sysctl, non-numeric contents); callers
/// must then decide explicitly rather than silently assuming a default. Compose
/// it with [`crate::fingerprint::os_network_coherence`] for a runtime-accurate
/// egress check.
#[must_use]
pub fn configured_host_initial_ttl() -> Option<u8> {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read_to_string("/proc/sys/net/ipv4/ip_default_ttl").ok()?;
        raw.trim().parse::<u8>().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Whether a persona's claimed OS is coherent with the TCP/IP stack of the
/// host this process egresses from, absent a TCP-OS-rewriting proxy.
///
/// The pre-flight L2 guard for the classic transport tell: selecting a Windows
/// persona (initial TTL 128) on a Linux egress host (initial TTL 64) yields a
/// [`NetworkOsCoherence::Mismatch`], so the operator knows the transport layer
/// will betray the persona unless a packet-rewriting proxy normalizes it. The
/// verdict is *returned*, not logged, a proxy may legitimately make a mismatch
/// a non-issue, so the caller owns how loudly to surface it. Returns
/// [`NetworkOsCoherence::Unknown`] when the host OS has no modeled stack.
#[must_use]
pub fn persona_host_network_coherence(profile: StealthProfile) -> NetworkOsCoherence {
    match host_initial_ttl() {
        Some(ttl) => os_network_coherence(profile, ttl),
        None => NetworkOsCoherence::Unknown,
    }
}
