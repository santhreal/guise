# Guise Tier-B persona-data tree

This directory is the **single shared persona-data tree** for the Santh stealth
stack (G100). All community-extensible, measured persona data lives here, not
duplicated in `guise-profiles`, `reynard`, or any other consumer.

## Layout

| Directory | Persona aspect | Loader |
|-----------|----------------|--------|
| `audio_devices/` | `navigator.mediaDevices` audio input/output labels | `guise::fingerprint::audio_device_tier_b` |
| `fingerprints/` | Real-browser TLS/H2 fingerprint targets for cluster membership | `guise::fingerprint::tls_targets::load_targets_from_toml` |
| `fonts/` | System font whitelists (engine `font.system.whitelist`) | `guise::fingerprint::font_tier_b` |
| `geo_regions/` | Coherent timezone/locale/coordinates/country presets | `guise::fingerprint::geo_region::load_geo_region_directory` |
| `profiles/` | Full browser+TLS profile bundles | `guise::fingerprint::ProfileBundle::from_toml` |
| `screen/` | Screen dimensions + device pixel ratio | `guise::fingerprint::screen_tier_b` |
| `voices/` | `speechSynthesis.getVoices()` voice lists | `guise::fingerprint::voice_tier_b` |
| `webgl/` | `UNMASKED_VENDOR_WEBGL` / `UNMASKED_RENDERER_WEBGL` GPU pairs | `guise::fingerprint::webgl_gpu_tier_b` |

## Contract

1. **One tree.** No other crate or project directory may maintain a second copy
   of the same persona data. `reynard` and other engine consumers read from this
   tree (directly or via the `guise` loaders), never re-implement it.
2. **Measured values only.** Every value must come from a real browser or device
   capture. Fabricated data creates empty uniqueness clusters and is worse than
   no data.
3. **Fail-closed loaders.** A malformed file rejects the entire load. No entry
   is silently skipped.
4. **Small files.** Each TOML is capped at 64 KiB to bound hostile/accidental
   drop-ins.

Adding a new persona aspect: create a new subdirectory, add a `tier-b-toml`-gated
loader in `guise::fingerprint::<aspect>_tier_b`, and add a regression test that
the shipped data loads and covers the expected platform families.
