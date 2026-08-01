# Trusted dependencies

Each external dependency that reaches the `guise` crate is pinned to a
workspace-level exact version where feasible and audited before it appears here.
Path dependencies are internal Santh crates and are governed by the workspace
review policy, not this file.

## Direct external dependencies

| crate | version source | feature usage | notes |
|-------|----------------|---------------|-------|
| anyhow | workspace | `browser` error context | standard error handling |
| chromiumoxide | workspace | `browser` CDP integration | headless Chromium launch / BiDi |
| futures | workspace | core async combinators | core dependency |
| http | workspace | `http-headers` typed header maps | HTTP 1.1 crate |
| proptest | workspace | dev | property tests |
| rand | workspace | core + sampling | deterministic seeding |
| reqwest | workspace | `reqwest-client` | optional high-level client |
| rustls | workspace | dev + `guise-echo` | TLS stack for echo tests |
| serde / serde_json | workspace | core serialization | canonical JSON/TOML |
| sha2 | workspace | `http-headers` header hashing | |
| thiserror | workspace | core error types | |
| tokio / tokio-rustls | workspace | `browser`, dev, echo tests | async runtime |
| toml | `=0.8.23` | `config`, `tier-b-toml` | Tier-A config + Tier-B persona hot-reload |
| tracing | workspace | `browser` launch diagnostics | only emitted on browser launch paths |

## Internal path dependencies

- `guise-choice`, `guise-pacing`, `guise-profiles`: co-owned persona subcrates.
- `guise-oracle`: canonical oracle types.
- `scanclient` (optional, `http` / `tls-impersonate`): provides TLS profile
  re-exports and the heavy BoringSSL impersonation transport.
- `runtime-foxdriver` (optional, `browser`): Firefox launcher wrapper.

## Known transitive advisories and remediation plan

| advisory | crate | transitive path | status | remediation |
|----------|-------|-----------------|--------|-------------|
| RUSTSEC-2026-0118 / RUSTSEC-2026-0119 | hickory-proto 0.25.2 | scanclient -> hickory-resolver | tracked | `scanclient` must upgrade `hickory-resolver` to `>=0.26.1` |
| RUSTSEC-2026-0002 | lru 0.13.0 | scanclient -> wreq-util -> wreq | tracked | `wreq` must upgrade or replace `lru` |
| RUSTSEC-2025-0057 | fxhash 0.2.1 | truestack -> scraper -> selectors | accepted | not on guise's build path; watch only |
| RUSTSEC-2024-0436 | paste 1.0.15 | runtime-foxdriver -> rustenium -> serde_valid | accepted | macro-only, no runtime effect; watch only |
| RUSTSEC-2026-0173 | proc-macro-error2 2.0.1 | same path as paste | accepted | macro-only, no runtime effect; watch only |
| RUSTSEC-2025-0134 | rustls-pemfile | was used by `guise-echo` | **resolved** | migrated to `rustls-pki-types` PEM parsing |

## Process

1. Run `cargo audit` (or `cargo deny check advisories`) at least once per session.
2. If a new advisory appears on a crate in guise's dependency tree, open a task
   against the owning crate first; only add an `ignore` entry here after the
   owner documents a remediation date.
3. Do not add new `ignore` entries for code that executes on the persona hot
   path without a concrete fix plan.
