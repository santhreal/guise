# guise: coherent browser persona substrate

![status: alpha](https://img.shields.io/badge/status-alpha-orange)

Canonical browser fingerprint bundles, human keystroke timing, TLS profile re-exports, and a full persona lifecycle for the Santh fleet.

Guise's categorical advantage is **one coherent persona end-to-end**: the same
identity drives JS navigator overrides, HTTP headers, TLS ClientHello, request
pacing, and behavioral timing, so no layer accidentally leaks a different
browser, OS, or geography (G319).

## What it does

`guise` provides six orthogonal stealth primitives that work together:

1. **Fingerprint bundles** (`fingerprint` feature, default) - Tier-A `ProfileBundle` values
   pair a `StealthProfile` (JS property overrides for navigator, WebGL, screen, etc.) with the
   matching TLS `ImpersonateProfile`. `profile_js` renders overrides into a CDP-injectable IIFE.
   `validate_overrides` / `validate_browser_coherence` detect UA/platform/brands mismatches before
   they reach a WAF.

2. **Human keystroke timing** (`human` feature, default) - `plan_keystrokes` produces a
   `Vec<Keystroke>` (char, hold_ms, gap_ms_before, is_correction) drawn from per-bigram timing
   envelopes calibrated on real human typing data. Supports typo injection with backspace
   correction and random thinking pauses. All timing is deterministic given a seeded `Rng`.

3. **TLS profile re-exports** (`http` feature, default) - thin re-exports of
   `scanclient::tls_impersonate::{ImpersonateProfile, supported_profiles}`. The heavier
   `StealthClient` (rquest + BoringSSL) is gated behind `tls-impersonate`.

4. **HTTP browser headers** (`http` + `fingerprint` + `rotation`, default) - ordered
   `User-Agent`, `Accept-*`, Client Hint, and `Sec-Fetch-*` templates derived from the same
   `StealthProfile` that drives browser JS overrides.

5. **Pacing and rotation** (`pacing` + `rotation`, default) - deterministic profile cycling,
   named profile resolution, exclusive-upper-bound jitter, and shared exponential backoff policy.
6. **Persona lifecycle + Tier-A config** (`config`, default) - `PersonaPool` owns select →
   assemble → bind transport → behavior → rotate for concurrent sessions, with sticky domains,
   burned-persona quarantine, snapshot/restore, and a defaults→TOML→CLI config surface.

Optional extras: CDP injection (`browser` feature) via `apply_stealth` / `apply_cdp_mask` for
a `chromiumoxide::Page`, Tier-B community TOML profiles (`tier-b-toml`), hot-reloadable
persona directories, and a stealth-probe scoring engine (`probe` module, `browser` feature).

## Quick start

Add to `Cargo.toml`:

```toml
guise = { path = "libs/runtime/guise" }
```

Generate a Chrome 131/Windows fingerprint + type "hello" with realistic timing:

```rust
use guise::{ProfileBundle, plan_keystrokes, TypingPlan};
use rand::{rngs::StdRng, SeedableRng};

let bundle = ProfileBundle::chrome_131_windows();
bundle.validate_browser_coherence().unwrap();

let mut rng = StdRng::seed_from_u64(0);
let keys = plan_keystrokes("hello", TypingPlan::default(), &mut rng);
assert_eq!(keys.len(), 5);
```

Inject the bundle into a chromiumoxide page (requires the `browser` feature):

```rust,ignore
use guise::browser::apply_stealth;

apply_stealth(&page).await?;  // call once, before goto()
```

## When to use / When not

**Use when:**
- You need a coherent UA + platform + brands + TLS fingerprint tuple (not just a UA string).
- You need human-realistic keystroke timing for CDP input dispatch.
- You want type-safe profile selection with compile-time coherence checking.

**Do not use when:**
- You need live browser fingerprint data (this crate ships static profiles; update them manually).
- You need full TLS impersonation without enabling the `tls-impersonate` feature - that feature
  pulls BoringSSL via `scanclient` and lengthens compile time significantly.
- You are working outside the Santh fleet and have no `scanclient` workspace dependency - the
  `http` feature will not resolve.

## Compared to alternatives

| Capability | guise | playwright-stealth | puppeteer-extra-stealth |
|---|---|---|---|
| Typed, validated profile bundles | yes | no | no |
| TLS ClientHello matching | yes (tls-impersonate) | no | no |
| Bigram keystroke timing | yes | no | partial |
| Zero outbound network | yes | yes | yes |
| Rust compile-time safety | yes | N/A (JS) | N/A (JS) |
| Live profile update | manual | community | community |

Unlike JS stealth libraries, this crate exposes typed Rust structs so the compiler catches
UA/platform mismatches before deployment.

## Threat model and honesty

Guise defends **fingerprint, network, and behavioral classifiers** by making every layer of
a persona derive from a single identity seed: navigator/WebGL overrides, HTTP headers,
TLS ClientHello, TCP/IP stack hints, request pacing, and keystroke/mouse timing. It does
**not** defeat human reviewers, CAPTCHA image challenges, or environment signals it cannot
control (e.g. a host OS TCP fingerprint that contradicts the persona). The `probe` module
(browser feature) continuously self-tests the disguise so marketing claims are backed by a
passing full-stack coherence test (G319).

## How it fits in Santh

`guise` is a **runtime substrate** consumed by the scanner and behavior layers:

```
libs/runtime/guise        ← this crate (fingerprint + timing data)
      ↑
libs/scanner/scanclient   ← HTTP client (uses ImpersonateProfile + StealthClient)
      ↑
libs/runtime/behavior/*   ← orchestration (uses ProfileBundle + plan_keystrokes)
      ↑
bin/santh                 ← operator entry point
```

Profile bundles flow outward via `scanclient` for TLS impersonation. Keystroke timing is
consumed directly by behavior orchestration that drives CDP input events. The `probe` module
(browser feature) runs in-page JS to score how detectable the active session is.

## Contributing

1. Pure profile data lives in `../guise-profiles/src/lib.rs`. Add a new
   `StealthProfile` variant, fill the profile facts, hardware tuple, navigator vendor,
   and Client Hint brand catalog entries there, then add a `ProfileBundle` constructor
   and extend `validate_tls_family` if the new browser family needs cross-checking.
2. Timing data lives in `src/human/keystroke.rs` in the `HOT_BIGRAMS` table and the
   `hold_envelope` match arms. Constants are named and documented; do not hardcode new values
   without a citation.
3. All new public items require a doc comment and at least one test in the appropriate
   `tests/` file (`unit/` for happy path, `adversarial.rs` for hostile input, `gap.rs` for
   pinned limitations, `property.rs` for proptest invariants, `integration.rs` for pipelines).
4. `cargo test -p guise` must pass before merging. Resolve any `fail`-level findings.

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
