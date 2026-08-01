use std::collections::HashSet;
use std::sync::Arc;

use super::*;
use crate::fingerprint::browser_catalog::PROFILES;
use crate::fingerprint::{NetworkOsCoherence, StealthProfile, UserAgentBrowser, UserAgentPlatform};

// Responsibility-split test submodules. Explicit `#[path]` because this file is
// itself `#[path]`-mounted (so a bare `mod x;` would resolve to
// `session_coherence/x.rs` and collide with the production `wire_probe`/`pool`
// modules); the `tests/` prefix keeps them in their own subtree. Each consumes
// the shared imports above via `use super::*`.
#[path = "tests/h2_akamai.rs"]
mod h2_akamai;
#[path = "tests/header_order.rs"]
mod header_order;
#[path = "tests/network_fingerprint.rs"]
mod network_fingerprint;
#[path = "tests/pairing.rs"]
mod pairing;
#[path = "tests/pool.rs"]
mod pool;
#[path = "tests/transport_coherence.rs"]
mod transport_coherence;
#[path = "tests/wire_probe.rs"]
mod wire_probe;
