//! Browser session coherence primitives for HTTP stealth transports.
//!
//! User-Agent, request-header order, HTTP/2 SETTINGS, and per-host profile
//! rotation have to agree. A Chrome user agent paired with Firefox header
//! order is still fingerprintable even when each individual layer looks
//! browser-shaped.
//!
//! Split by responsibility (Law 5), every public item is re-exported here so
//! the `http::session_coherence::*` path is unchanged:
//! - [`profiles`] (per-engine wire DATA: header order + HTTP/2 / Akamai model).
//! - [`transport`] (transport-coherence predicates (TCP/IP ↔ H2 ↔ header ↔ TLS)).
//! - [`persona`] (the unified JS-to-wire persona gate + host network-OS checks).
//! - [`wire_probe`] (the X049 self-probe of our own egress vs the persona).
//! - [`pool`] (per-host profile assignment with bounded session lifetime).

#[path = "session_coherence/persona.rs"]
pub mod persona;
#[path = "session_coherence/pool.rs"]
pub mod pool;
#[path = "session_coherence/profiles.rs"]
pub mod profiles;
#[path = "session_coherence/transport.rs"]
pub mod transport;
#[path = "session_coherence/wire_probe.rs"]
pub mod wire_probe;

pub use persona::{
    configured_host_initial_ttl, host_initial_ttl, host_platform, persona_full_stack_coherence,
    persona_host_network_coherence, PersonaIncoherence,
};
pub use pool::SessionPool;
pub use profiles::{
    pair_for_name, pair_for_profile, H2Profile, HeaderOrder, CHROME_H2, CHROME_HEADER_ORDER,
    FIREFOX_H2, FIREFOX_HEADER_ORDER, SAFARI_H2, SAFARI_HEADER_ORDER,
};
pub use transport::{
    persona_transport_coherence, transport_coherence_for_profile, transport_family_for_browser,
    TransportCoherence, TransportIncoherence,
};
pub use wire_probe::{persona_wire_self_probe, WireCapture, WireLayerMismatch, WireSelfProbe};

// Internal seam the test module drives with hand-built overrides. Only the test
// build consumes the re-export, so gate it there (else it is an unused import in
// every non-test consumer of the crate).
#[cfg(test)]
pub(crate) use persona::full_stack_coherence_of;

#[cfg(test)]
#[path = "session_coherence/tests.rs"]
mod tests;
