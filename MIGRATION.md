# Migration Guide

This document tracks breaking changes to guise's public API and the migration
path for consumers (G315/G316).

## Policy

- guise follows **compatibility-by-contract** (Law 3). Public types and
  functions are kept stable across minor versions; breaking changes only happen
  when the persona schema itself must evolve, and this file records the path.
- Deprecated items are kept for at least one minor release with a
  `#[deprecated]` attribute and a note pointing to the replacement.

## 0.1.x → current

### Persona lifecycle and configuration

- The persona lifecycle now lives in `guise::persona_pool`. Consumers that
  previously assembled `ProfileBundle` values directly can still do so, but
  concurrent-session management, domain stickiness, burned-persona quarantine,
  and snapshot/restore should go through `PersonaPool`.
- Tier-A configuration moved to `guise::config::GuiseConfig`. Replace ad-hoc
  `RotationPolicy` / `RequestPacer` construction with
  `GuiseConfig::default().with_*()` or `GuiseConfig::from_toml_file(path)`.
  The precedence chain is: hard-coded defaults → TOML file → CLI override.

### Feature flags

- The `browser` feature now implies `human` and `pacing` because the probe and
  behavioral layers depend on them. Single-feature builds that previously
  expected `browser` without `human` should enable `human` (or use the default
  feature set).
- The new `config` feature is enabled by default. Consumers using
  `--no-default-features` who want the configuration surface must enable
  `config` explicitly.

### Internal-only changes (no consumer action)

- `ProfileBundle::from_seed` is unchanged; seeds remain reproducible.
- `RotationPolicy` variant names and semantics are unchanged.
- The `RequestPacer` API is unchanged.

## Future migrations

When a new persona schema field is added, the migration entry will list:

1. The new field and why it was added.
2. Whether the field is optional with a default or required.
3. The Tier-B TOML key, if applicable.
4. Any removed fields and their replacements.
