# guise Progress Log

This file records concrete evidence for closed G-tasks per the completion
contract in `planning/stealth-stack/02-guise.md`.

## Section X: Evasion farble correctness (2026-06-18)

A behavioral audit of `fingerprint::evasion` (the stock-Firefox JS noise layer)
surfaced that the unit tests only string-matched the emitted JS, none executed
it: so several defects were invisible. Added a Node behavioral oracle
(`tests/evasion_farble_node_oracle.rs`) that runs the emitted IIFEs against stub
DOM prototypes, then fixed what it caught:

- **[CRITICAL] ASI IIFE concatenation.** `evasion_js_source` joined per-surface
  IIFEs with bare `"\n"`; `})()`⏎`(function(){…})()` parses as a call of the first
  IIFE's `undefined` return → `TypeError` aborts the whole preload. In the shipped
  default config only canvas (the first IIFE) ran; **audio + font + WebGL evasion
  never applied in a real browser.** Fixed: `scripts.join(";\n")` + trailing `;`.
  Regression: `full_evasion_source_evaluates_without_aborting` (evals the all-axes
  source under Node; the bare-`\n` form throws).
- **Canvas `getImageData` / `OffscreenCanvas` recall hole.** Noise lived only in
  `toDataURL`/`toBlob`; the primary pixel-read path was undefended. Now a shared
  coordinate-keyed deterministic farble covers `CanvasRenderingContext2D` and
  `OffscreenCanvasRenderingContext2D` `getImageData` + the serialization path 
  session-stable, coherent across regions, unlinkable across sessions.
- **Audio `OfflineAudioContext` recall hole + own-property tell.** Replaced the
  per-instance `createAnalyser→getFloatFrequencyData` wrap (own-property tell,
  missed the canonical `AudioBuffer.getChannelData` path) with prototype-level,
  idempotent (WeakSet) farble of `AudioBuffer.prototype.getChannelData` and
  `AnalyserNode.prototype.{getFloatFrequencyData,getFloatTimeDomainData}`.
- **`measureText` font-fingerprint recall hole.** The dominant font-detection
  method was undefended. Added uniform per-session `TextMetrics` scaling (O(1), no
  timing tell) that perturbs the exact-width vector while preserving font-presence
  detection and layout. Replaced the old `FontFaceSet.forEach` skip, which only
  touched page-loaded faces and made the iterated count disagree with
  `document.fonts.size` (a guise-introduced coherence tell, now removed).
- **Session-noise probe semantics.** The canvas/audio probes rewarded per-read
  *instability* as Pass, but that is itself a tell and a correct deterministic
  farble never produces it. Renamed to "… session-stable (no per-read tell)" and
  inverted `classify_session_noise` (stable = Pass) (consistent with `creepjs`).
- **Three must-cover probes added** (`RTCPeerConnection.createOffer`,
  `navigator.mediaDevices.getUserMedia`, `AnalyserNode.getFloatFrequencyData`),
  shrinking the honest `uncovered_must_cover` gap to `navigator.gpu.requestAdapter`.

Validation: `cargo test -p guise --features browser,http,tier-b-toml --tests`:
**1111 passed, 0 failed** (993 lib + integration). `--doc`: 12 passed. Node oracle:
2 passed. Feature matrix (`fingerprint`/`human`/`http-headers`/`config`/default)
builds clean. Downstream `cargo check` of `captchaforge` passes.

## Section X2: Identity + behavioural execution audit (2026-06-19)

Same "execute it, don't string-match it" rigor applied to the two other paths
with no offline behavioural coverage:

- **`profile_js` identity oracle (new, `tests/profile_js_node_oracle.rs`).** Every
  block in `profile_js` is wrapped in `try {…} catch (_) {}`, so a block that
  throws in a real engine silently ships that surface UN-spoofed. The oracle evals
  every shipped profile's JS in a fresh Node `vm` realm and asserts the resulting
  navigator/window/Intl state (UA, platform, vendor, language==languages[0],
  hardwareConcurrency, innerWidth/Height, userAgentData present-for-Chromium /
  absent-for-Firefox, Intl persona timezone, native getter `toString`). Result:
  **all profiles coherent, no silently-dropped block** (a real blind spot closed).

- **Live mouse driver was using the detectable Bézier; the real-trace corpus was
  dead code.** `HumanMouse::move_to` built its path from a single cubic Bézier (the
  exact constant-curvature signature `mouse.rs` documents as ML-flaggable), while
  the real-human `MouseSampler` corpus it was meant to use was referenced ONLY by
  its own tests. The corpus could not drive a click because `sample()` random-walks
  its endpoint up to ~100px off-target (uncompensated per-step jitter, a real bug;
  the test even tolerated ±100px). Added `MouseSampler::resampled_path` (affine-maps
  a real trace's cumulative shape, lands EXACTLY on target, persona-scaled interior
  wander), pointed the live driver at it, fixed the `sample()` drift, removed the
  dead `cubic_bezier`. Timing/easing/overshoot/telemetry/trusted-dispatch unchanged.
  Pure-Rust tests assert exact landing, real curvature (>2px deviation from the
  straight line), finiteness, and zero-length safety.

Validation: `--tests` **1112 passed, 0 failed**; downstream `captchaforge`
`cargo check` passes.

## Section D: Probe / oracle expansion

### G182: Three-way oracle comparison (stock vs reynard vs JS-disguise)

- Added `three_way_compare` to `probe::oracle`: diffs stock Firefox, patched
  reynard, and the JS disguise captures surface-by-surface.
- New `ThreeWayReport` / `ThreeWaySurface` types classify each surface as an
  **engine win** (stock == reynard != disguise), a **JS win** (stock == disguise
  != reynard), or **everyone loses** (all three differ).
- Added `render_three_way` for human-readable output.
- Unit tests cover engine win, JS win, everyone-loses, agreement, and error
  handling.
- Integration test in `tests/oracle_fixture.rs` uses the synthetic fixture to
  prove the engine patch is closer to stock than the JS disguise.

### G192: CreepJS trust-score probe

- Added `probe::creepjs` module (`src/probe/creepjs.rs`) with a catalogue probe
  that computes a CreepJS-style trust score from live integrity checks.
- Penalty model mirrors CreepJS weighting: `navigator.webdriver === true` (−45),
  empty plugins/MIME (−20/−10), SwiftShader renderer (−25), empty timezone
  (−20), automation globals and error-stack markers (−15 each), unstable
  canvas/audio, and low voice count.
- Classifier thresholds: ≥80 `Pass`, 40–79 `Drift`, <40 `Critical`.
- Unit tests cover all three outcome classes, non-numeric handling, and catalogue
  membership for both Chromium and Firefox families.

### G202/G203: Network-layer oracle surfaces

- Added `probe::transport` module (`src/probe/transport.rs`, `http-headers`
  feature) with `TransportFingerprint` and `compute_transport_fingerprint`.
- Computes JA3/JA4 from `tls_profiles`, JA4T/p0f signature from the persona's
  `OsNetworkStack`, and H2 Akamai/Peet fingerprints from `tls_targets`.
- `transport_capture` / `enrich_capture` expose transport surfaces as
  `CapturedSurface` values the oracle diffs surface-by-surface.
- Unit tests verify Firefox-150 vs Chrome-146 transport divergences are
  reported for `transport.ja3`, `transport.ja4`, and `transport.h2_akamai`.

### G211: Convert gaps to catalogue probes

- Added Firefox probe `navigator.userAgentData absent or brands empty
  (Firefox)` (`classify_user_agent_data_empty_or_absent`) that closes the
  `firefox_profiles_brands_empty_pins_no_client_hints` gap from `tests/gap.rs`.
- The existing `navigator.hardwareConcurrency in [2, 16]` probe already
  continuously catches the `validate_overrides_does_not_check_hardware_
  concurrency_range` gap; added a unit test proving it flags 0 and 10000.
- Source-level gaps that are not runtime browser surfaces (qwerty_neighbour
  digit coverage, typing-plan saturation, SafariIpad mobile approximation,
  profile_js availHeight offset audit) remain pinned by `tests/gap.rs` so a
  future change is deliberate.

### G212: Grow adversarial-evasion suite

- Added adversarial checks in `tests/adversarial.rs` for the new oracle pieces:
  - `behavioral_fingerprint_extreme_seeds_do_not_panic`: boundary seeds 0,
    1, `u64::MAX`, `u64::MAX-1`.
  - `transport_capture_for_safari_has_no_h2_but_still_has_tls_and_tcp`: a
    profile with no measured H2 target must still emit TLS/TCP surfaces.
  - `full_stack_compare_handles_label_mismatch_gracefully`: mismatched layer
    labels do not panic and adopt the JS capture labels.

### G216: Severity auto-tuning from detector verdicts

- Added `SeverityTuner` to `probe::scorecard` with configurable `boost` and
  `max_weight`.
- `tune` / `tune_str` accept a list of surface-ids/probe-names that a real
  detector/WAF reported as contributing to a block/challenge, and increase the
  corresponding scorecard weights conservatively (capped, never decreasing).
- Unit tests prove boosting raises `lost_points` and the cap prevents runaway
  weights.

### G204/G205/G206: Full-stack oracle (JS + transport + behavioral)

- Added `probe::behavioral` module (`src/probe/behavioral.rs`) with
  `BehavioralFingerprint` sampled deterministically from a seed.
- Surfaces: typing avg hold/gap, typo count, action-delay bounds,
  `delays_are_distributed`, and an aggregate `realism_score`.
- Added `FullStackReport` to `probe::oracle` with separate JS / transport /
  behavioral layer reports and `combined_scorecard` that merges them into one
  scorecard for CI regression gating.
- `tests/oracle_fixture.rs` regression-locks a full-stack comparison using the
  synthetic JS fixture + real persona transport + seeded behavioral captures,
  proving the merged scorecard accumulates points from all three layers.

### G207/G208: Production drift detector + auto-bisect

- Added `probe::drift` module (`src/probe/drift.rs`) with `DriftDetector`,
  `DriftSnapshot`, `DriftEvent`, and `BisectReport`.
- The detector is anchored to a known-good reference snapshot and compares a
  baseline snapshot against a current snapshot, reporting **new** divergences,
  **recovered** divergences, and surfaces that are **still diverging**.
- Configurable alert threshold (`High` by default, overridable to `Medium` or
  `Low`) so a periodic probe run pages operators only when a meaningful tell
  appears.
- `BisectReport` attributes new drift to the changed layer (`Js` / `Transport` /
  `Behavioral`), the persona override fields responsible (via the G119
  `SPOOF_SURFACE_LINKS` bridge), or engine-level surfaces, and reports
  `PersonaContext` deltas (profile, UA, platform, TLS profile, OS stack, seed).
- Unit tests cover: clean snapshots, new/recovered/still/changed-value
  divergences, severity threshold boundaries, layer attribution, persona-field
  attribution, engine-surface attribution, context-delta rotation detection,
  scorecard generation, and JSON serialization round-trip.

### G209/G210: Consolidate live tests into one oracle-driven suite

- Replaced `tests/differential_oracle.rs`, `tests/headful_truth.rs`,
  `tests/headless_tells.rs`, and `tests/stealth_core_tells.rs` with a single
  `tests/oracle_live.rs` (G209).
- The unified suite is driven by the shared surface catalogue:
  `diff_pages` covers stock-vs-stock soundness and stock-vs-disguise residual
  tells; `run_for` covers the automation-tell overlap that was previously
  hand-rolled in `stealth_core_tells.rs` (G210).
- Kept the focused regression tests that are not catalogue assertions:
  native-code `toString` sealing and session-age seeding.
- Headful GPU truth and headless-sensitive surface dumps live as optional
  diagnostics inside the same suite, activated by `HEADFUL_GPU=1` and
  `STEALTH_FIREFOX` respectively.
- Updated `Cargo.toml` test target list to point to `oracle_live` and removed
  the obsolete explicit entries.

### G213: Catalogue completeness critic

- Added `probe::completeness` module (`src/probe/completeness.rs`) with a
  curated `KNOWN_FINGERPRINTER_CHECKS` list drawn from CreepJS, fpcollect,
  sannysoft, and common WAF anti-bot scripts.
- `coverage_report(browser)` matches known checks against `probes_for(browser)`
  and reports covered count, coverage percentage, and `CoverageGap`s.
- Checks are tagged with the browser families they apply to, so a Chromium-only
  check is not reported as a Firefox gap.
- Criticality levels (`Critical` / `High` / `Medium`) let CI fail only on
  uncovered hard automation/identity tells while accepting lower-priority gaps
  as data.
- Unit tests assert all Critical checks are covered for both Chrome and Firefox,
  that the count arithmetic is consistent, and that Chrome-only checks do not
  leak into the Firefox report.

### G183: Catalogue expansion to 200+ surfaces

- Added `probe::catalogue_extended` module (`src/probe/catalogue_extended.rs`)
  with 35 additional runtime probes across WebGPU, Permissions API, Intl APIs,
  performance/memory, navigator/device extensions, storage, sensors, and
  lifecycle surfaces.
- Wired into the family-aware catalogue; total probe count is now **201**.
- Raised `PROBE_COUNT_FLOOR` from 100 to 200 to enforce the new bar and catch
  silent probe drops.
- Unit tests verify uniqueness, substantial size, and High-severity placement of
  the WebGPU requestAdapter probe.

### G199: BiDi-specific tell probes

- Added `probe::bidi_tells` module (`src/probe/bidi_tells.rs`) with six probes
  targeting WebDriver BiDi footprints: `__webdriver_evaluate`,
  `__webdriver_script_fn`, `__webdriver_script_function`, stack markers for
  `webdriver_evaluate` and `bidi_script`, and inherited `navigator.webdriver`.
- Wired into the family-aware catalogue so every probe run includes these BiDi
  checks.
- Unit tests cover uniqueness, severity, and classifier boundaries.

### G190: Offline oracle fixture for deterministic CI

- Refactored `probe::oracle` so capture and diff are separate:
  `capture_page` produces a serializable `Capture`; `diff_captures` diffs two
  captures without a live browser.
- Added `probe::fixture` (`src/probe/fixture.rs`) with a synthetic Firefox
  capture pair modeling stock vs JS-disguise divergences.
- Added `tests/oracle_fixture.rs` (G190) asserting deterministic report
  rendering, scorecard serialization, and critical-surface prioritization from
  the offline fixture.
- The fixture can be replaced by a real `capture_page` JSON capture when an
  operator runs the live gate.

### G181 / G217: Shared taxonomy scorecard for the oracle

- Added `probe::scorecard` module (`src/probe/scorecard.rs`) with a versioned,
  serializable `Scorecard` schema.
- Every `Divergence` now carries an optional `surface_id` from the shared
  inventory taxonomy (`src/fingerprint/surface.rs`).
- `DifferentialReport::to_scorecard(browser)` converts oracle output into the
  shared scorecard format.
- The scorecard is the cross-crate contract intended for reynard CI, captchaforge
  gating, and `guise bench` (G305/G306/G307).

### G184: Severity weights calibrated to detector criticality

- `scorecard::weight_for_surface` maps inventory `Criticality` to weights:
  `Critical = 100`, `High = 40`, `Medium = 10`, `Low = 2`.
- Probes not bridged to the inventory fall back to catalogue `Severity` weights:
  `High = 30`, `Medium = 8`, `Low = 1`.
- Unit test `weight_table_matches_criticality_calibration` pins the mapping.

### G195 / G196: Benchmark impact + auto-prioritization

- `ScorecardEntry::benchmark_points` equals the calibrated weight, giving a
  direct scoreboard cost per divergence.
- `Scorecard::prioritized_fixes()` returns divergences sorted by lost points
  (descending), engine-level tells before persona-intended ones, then surface-id.
- Unit tests verify the ordering and that `navigator.webdriver` tops the fix list.

## Section D: Probe / oracle expansion (closure)

### G214: CreepJS / fpcollect / sannysoft source crawl

- Crawled public anti-bot check lists (HackingLZ/fingerprint_js, CreepJS,
  sannysoft-class check matrices) and expanded `KNOWN_FINGERPRINTER_CHECKS` in
  `src/probe/completeness.rs` with 20 additional checks across chrome-object
  integrity, automation globals, navigator inheritance, UA-CH coherence,
  timezone coherence, touch/DPR, error-stack presence, canvas/audio integrity,
  network information, notifications, Math IEEE-754, `document.hasFocus`,
  permissions, brave detection, WebRTC, and window dimensions.
- Mapped each new check to a stable `probe_pattern` substring; Critical checks
  must match an existing catalogue probe, Medium/High checks may be tracked gaps.
- `coverage_report` still asserts zero Critical gaps for both Firefox and Chrome.
- Added a source-crawl note to the module doc comment so future expansion is
  tied to the public check lists.

### G219: Oracle runtime budget (parallel probe eval over BiDi)

- `probe::run_for` now builds one async evaluation future per probe and drives
  them concurrently with `futures::future::join_all`.
- `probe::oracle::capture_page` already evaluates the catalogue concurrently;
  both paths preserve catalogue order in their output so diffs/renderings stay
  deterministic.
- The slow probe dominates runtime instead of the sum of probe latencies,
  bringing oracle page-evaluation time down to ~one BiDi round-trip budget.

### G220: Publish the oracle as a reusable surface taxonomy crate

- Created `libs/runtime/guise-oracle`, a lightweight contract crate with no
  browser-driver, TLS, or behavioral dependencies.
- Moved the core oracle taxonomy types into `guise-oracle::types`:
  `Severity`, `Determinism`, `ProbeOutcome`, `Probe`, `DriftReport`,
  `ProbeReport`, `CapturedSurface`, `Capture`, `DivergenceKind`, `Divergence`,
  `DifferentialReport`, `ThreeWaySurface`, `ThreeWayReport`.
- `guise::probe` now re-exports these types; runtime evaluation and rendering
  logic remains in `guise`.
- Added workspace member + dependency entries for `guise-oracle`.
- Added unit tests for severity ordering, outcome class labels, JSON
  round-trip, and the green threshold.
- Downstream consumers (`reynard`, `sear`, `captchaforge`) can now depend on
  `guise-oracle` for the shared surface contract without pulling in the full
  stealth stack.

## Section E: Rotation / pacing / sampling / coherence

### G227 / G228: Request pacing integrated with behavioral timing

- Added `RequestPacer` to `guise-pacing` (`libs/runtime/guise-pacing/src/lib.rs`).
  It is the single model for both HTTP request pacing and behavioral think-time.
- Profiles:
  - `RequestPacer::page_load()` → 800–3 000 ms
  - `RequestPacer::sub_resource()` → 100–400 ms
  - `RequestPacer::api_call()` → 300–1 200 ms
- Samples from `BoundedNormalDelay` (same primitive used by `ActionDelay`).
- Added positive, boundary, and adversarial tests in `guise-pacing`:
  - delays stay within profile bounds;
  - default is not a fixed sleep (many distinct samples);
  - challenge multiplier doubles on 429/403 and decays on 2xx;
  - multiplier is capped at `MAX_CHALLENGE_MULTIPLIER`.

### G229: Rate-limit-aware pacing

- `RequestPacer::record_http_status(status)` treats `429` and `403` as
  rate-limit/challenge signals and doubles `challenge_multiplier`.
- Successful `2xx` responses decay the multiplier by one step.
- `next_delay(rng)` returns `base_delay * challenge_multiplier`, so a challenged
  persona slows down like a human would.

### G230: No fixed sleeps in pacing path

- `RequestPacer` profiles always use a bounded normal distribution with
  `min_ms != max_ms`.
- Added `request_pacer_default_is_not_a_fixed_sleep` test asserting >50 distinct
  delays from 100 samples.
- Refactored `human::timing::ActionDelay` to use `BoundedNormalDelay`, and added
  `action_delays_are_not_fixed_sleeps` test asserting the same.

### G223: Rotation policy

- Added `RotationPolicy` enum to `src/rotation.rs` with `Never`, `PerSession`,
  `PerTarget`, and `PerRequests(u64)` variants.
- Added `RotationState` to track the previous target and the request count with
  the current persona.
- `RotationPolicy::should_rotate(&state, current_target)` decides when to rotate
  before a request; `record_request` updates state after a request.
- Unit tests cover: `Never` always returns false, `PerSession` rotates only once,
  `PerTarget` rotates on target change, `PerRequests(n)` rotates every `n`
  requests, boundary cases (`n = 0`, `n = 1`), and state mutation.

### G225 / G226: Unified RNG/seed source

- Added `Seed`, `seed_from_u64`, `seeded_rng`, and `seeded_rng_from_u64` to the
  `guise-choice` subcrate so every downstream sampler can share one deterministic
  seed type.
- Added `RngSeed` to `guise::sampling` with `from_u64`, `from_bytes`, and
  `derive(label)` for labelled sub-seeds, letting one persona seed feed rotation,
  profile selection, behavior, and fingerprint layers without cross-correlation.
- Added `fingerprint::identity::seeded(seed)` for deterministic persona assembly
  and `seeded_weighted(seed)` for rarity-biased selection.
- Unit tests prove byte-seed expansion, deterministic reproduction, label-based
  derivation, and independent derived streams.

### G231 / G232: Weighted persona selection

- Implemented `fingerprint::identity::seeded_weighted` using
  `guise_choice::weighted_index_by_with_rng` with `rarity_score` weights.
- Modal personas (e.g. ChromeWindows, FirefoxLinux) are selected far more often
  than rare personas (e.g. IE11) while every shipped template retains a non-zero
  chance.
- Distribution test over 10k seeds asserts the modal/rare ratio and that every
  built-in profile appears at least once.

### G221 / G222 / G224: Rotation coherence tests

- Added unit tests in `src/rotation.rs` proving:
  - `every_rotated_profile_builds_a_coherent_bundle`: each rotated profile
    produces a `ProfileBundle` that passes the full coherence gate (G221).
  - `rotation_changes_js_identity_across_profiles`: consecutive profiles differ
    in their user-agent string, so the JS layer reflects the new persona (G222).
  - `rotation_changes_transport_fingerprint_across_different_families`: Chrome
    vs Firefox rotation changes JA4 and H2 fingerprints, so the transport layer
    reflects the new persona (G222).
  - `rotation_never_mixes_persona_a_js_with_persona_b_tls`: a bundle built from
    one profile never contains another profile's JS UA, guarding against the
    classic mixed-persona tell (G224).

### G233–G244: Persona lifecycle pool

- Implemented `src/persona_pool.rs` as the single owner of select → assemble →
  bind transport → behavior → rotate (G233).
- `acquire`/`release` increment/decrement an in-flight counter; `rotate` refuses
  to run while in-flight > 0 (G240).
- Domain bindings make repeated visits to the same target reuse the same session
  (G241/G242), proven by `sticky_domain_reuses_session` and
  `different_domains_get_distinct_sessions`.
- `mark_burned` removes domain bindings and records the seed in `burned_seeds`;
  `restore_snapshot` rejects burned seeds, so a blocked persona stays quarantined
  across restarts (G243/G244).
- Concurrent sessions are deduplicated by identity key when the built-in template
  pool allows (G235/G236), tested by
  `concurrent_sessions_have_distinct_identities`.
- `PersonaSession` caches `ProfileOverrides` and `ProfileBundle` so derived values
  are not rebuilt per request (G237).
- `snapshot` and `restore_snapshot` preserve seed and request count (profile age)
  across process restarts (G238/G239), tested by
  `snapshot_round_trip_preserves_identity` and
  `request_count_is_preserved_by_snapshot`.
- Added `PoolConfig::max_concurrent_sessions` and `PoolError::AtCapacity` with a
  test proving new sessions are blocked at the limit while existing domain bindings
  remain usable.

### G245–G250: Tier-A config + hot reload + stable API

- Added `src/config.rs` behind a new `config` feature (default-enabled) with
  `GuiseConfig`, `RotationConfig`, `PacingConfig`, and `PoolConfig` (G245).
- Config precedence is explicit and tested: defaults → TOML file → CLI override
  (`precedence_default_then_file_then_cli`) (G246).
- Added `GuiseConfig::from_toml_file`, `from_toml_str`, and `with_*` builders for
  every Tier-A knob; TOML round-trip and invalid-pacing-boundary tests lock the
  parser.
- `GuiseConfig::to_pool_config` converts config directly into `persona_pool::PoolConfig`.
- Added `TierBPersonaDir` under the `tier-b-toml` feature to scan a directory of
  persona TOMLs and reload when a new file appears (G247/G248), tested by
  `tier_b_dir_scans_toml_files` and `tier_b_reload_detects_new_file`.
- Documented the full lifecycle + config surface in `src/config.rs` module docs
  and added a TOML example (G249).
- The `config` module is a public, stable API entry point for consumers
  (`guise::config::*`) (G250).

### G185 / G186: Red-team probe expansion

- `probe::redteam` gained `HTMLIFrameElement.contentWindow` and
  `Permissions.prototype.query` native-code checks.
- Both use `classify_must_be_native_code`; unit tests cover pass/fail boundaries.

### G188: Media/codec capability matrix

- `probe::codec` now awaits `MediaCapabilities.decodingInfo` for AAC and Opus.
- Classifier treats a missing/denying MediaCapabilities stack as a `Drift`.

### G189 / G218: Oracle determinism

- `probe::oracle::render_differential` sorts divergences defensively before
  rendering; golden/diffable output is unit-tested.

### G191: Live-probe skip-loud audit

- All browser-spawning live tests audited; each skips loudly with the required
  env var and reason when its opt-in condition is not met.

### G193 / G194 / G198: Lie-detector probe set

- New `probe::lie_detector` detects descriptor / toString inconsistencies.
- Classifier targets zero lies (`Pass` for empty, `Drift` for 1–2, `Critical` for
  3+); unit + opt-in live regression tests.

### G200 / G201: Worker / ServiceWorker / Worklet realm probes

- New `probe::realm` probes cross-realm navigator coherence.
- Classifier flags mismatches in `userAgent`, `platform`, `language`,
  `hardwareConcurrency`, `productSub`, `webdriver` as `Drift` or `Critical`.

## Section F: Test matrix, bloat, dedup, wiring, ship (partial closure)

### G253: Proptest 10k+ coherent personas

- Added `any_seed_produces_a_coherent_bundle` in `tests/property.rs` configured
  with `ProptestConfig::with_cases(10_000)`. Every random `u64` seed builds a
  `ProfileBundle::from_seed` and passes `validate_browser_coherence`.

### G256: Scale corpus

- Added `scale_corpus_10000_personas_are_coherent` to `tests/property.rs`. It
  assembles and validates 10,000 personas and prints throughput
  (ms/persona). All 10,000 passed.

### G260: Malformed Tier-B TOML rejected loud

- Added `tier_b_toml_malformed_is_rejected_loud` and
  `tier_b_toml_incoherent_browser_tls_is_rejected_loud` to
  `src/fingerprint/bundle/tests.rs`. Both assert the error message explains the
  failure (parse or browser/TLS mismatch) rather than silently defaulting.

### G263: Doctest examples for public API

- Added runnable doctest examples to `src/config.rs`, `src/persona_pool.rs`,
  and `src/fingerprint/bundle.rs::ProfileBundle::from_seed`.
- `cargo test -p guise --doc` passes (12 doctests).

### G268: Cross-file A-to-B: source → headers → TLS → probe

- Existing `tests/unit/profile_bundle.rs::persona_seed_flows_unmodified_through_bundle_headers_and_tls`
  is the canonical cross-file trace: `profile_facts` → `ProfileBundle` →
  `validate_full_coherence` → `browser_profile` headers, asserting the same
  identity reaches every layer unmodified.

### G269: CVE-replay: dead-JS-layer bug stays fixed

- `src/fingerprint/bundle/tests.rs::profile_js_is_syntactically_balanced_for_all_profiles`
  and the opt-in live `tests/profile_js_live_eval.rs` continuously replay the
  CHANGELOG dead-layer class. The swallow path is also locked by source-audit
  guards (G262).

### G281 / G283: Tier-A flag wiring

- `GuiseConfig::to_pool_config` proves every configured rotation policy and
  concurrency limit reaches `persona_pool::PoolConfig`.
- `precedence_default_then_file_then_cli` and `to_pool_config_matches_rotation_policy`
  prove CLI/file overrides have observable effects on the pool.
- Pacing overrides reach the returned `RequestPacer`
  (`request_pacer_uses_configured_page_load_bounds`).

### G284 / G296: README and threat-model coherence

- Updated `README.md` to use the correct crate name (`guise`), added a
  "Threat model and honesty" section stating what guise defends and what it does
  not, and refreshed the headline to state the categorical advantage with a
  test-backed claim (G318/G319).

### G295: Cargo.toml feature graph documented

- `src/lib.rs` feature table already documents which feature pulls what; added
  the new `config` feature to the table.

### G301 / G302: Unit tests for TLS re-export and bundle assembly

- `tests/unit/tls_reexport.rs` asserts `ImpersonateProfile::parse` round-trips
  and lists supported profiles.
- `tests/unit/profile_bundle.rs` asserts every rotation profile assembles into a
  coherent bundle and that the persona seed flows unmodified through headers and
  TLS.

### G313 / G314: Seed logging surface + reproducibility

- `PersonaSession::seed()` exposes the seed for logging/debug.
- Added `persona_pool::tests::same_seed_reproduces_identical_persona` proving a
  snapshot/restored seed yields the exact identity.

### G255: Criterion hot-path benchmarks

- Added `criterion` dev-dependency and `benches/persona_hot_paths.rs` covering
  `profile_js` generation, header build, bundle assembly, keystroke planning,
  and request-pacer sampling. `cargo bench -p guise --no-run` compiles cleanly.
  Also fixed a feature-gate bug exposed by the bench build:
  `rotation_changes_transport_fingerprint_across_different_families` now requires
  both `http-headers` and `browser` because it uses `crate::probe`.

### G257 / G258 / G259: Feature flag builds and tests

- Verified every required feature flag builds and its lib tests pass:
  `fingerprint`, `human`, `pacing`, `rotation`, `config`, `http-headers`,
  `reqwest-client`, `tls-impersonate`, `browser`, `tier-b-toml`.
- Fixed two feature-graph bugs discovered during the matrix check:
  - `browser` now depends on `human` (the probe/behavioral layer uses it).
  - `human` now depends on `pacing` (`human::timing` uses
    `pacing::BoundedNormalDelay`).

### G264: Integration coverage

- Added `config_drives_pool_lifecycle` to `tests/integration.rs`, proving a
  `GuiseConfig` converts into a working `PersonaPool` and that the configured
  capacity limit has observable behavior.

### G266: Fuzz-style parser resilience

- Added adversarial tests that feed 256 random byte strings to
  `ProfileBundle::from_toml`, 256 random strings to
  `ImpersonateProfile::parse`, and every shipped profile to the header builder,
  asserting no panic on any input.

### G315 / G316: Migration guide + compatibility-by-contract

- Added `MIGRATION.md` documenting the breaking-change policy and the migration
  path for the new persona pool / configuration surface.

### G299: Dependency CVE scan / trusted-deps hygiene

- Migrated `guise-echo` from unmaintained `rustls-pemfile` to
  `rustls::pki_types::pem::PemObject` (`rustls-pki-types`).
- `cargo tree -p guise-echo -e normal` confirms `rustls-pemfile` is gone.
- `cargo audit` no longer reports `RUSTSEC-2025-0134` for `guise-echo`.
- Added `deny.toml` + `TRUSTED_DEPS.md` documenting accepted transitive
  advisories (`hickory-proto`, `lru`) and the plan to push fixes to the owning
  crates (`scanclient`, `wreq`).

### G275 / G276 / G277 / G280 / G282. Dedup + module-pair audit

- `tier_b/README.md` documents the single shared persona-data tree consumed by
  guise and reynard (G275).
- The surface taxonomy is shared via `fingerprint::surface::SurfaceId` and the
  `probe::surface_coverage` bridge (G276/G282).
- `fingerprint::ja4_hash` is the single primitive feeding both `ja3` and
  `ja4_family` (G277).
- Cross-file A-to-B tests (`persona_seed_flows_unmodified_through_bundle_headers_and_tls`,
  `config_drives_pool_lifecycle`, and the persona-pool lifecycle tests) audit
  the hot-path module pairs (G280).

## Section F: Ship / bridge / cross-crate closures

### G251 / G252 / G254 / G270: Live-detector acceptance suite + scorecard

- Added `tests/live_detector_suite.rs` (gated by `REYNARD_BIN` + `DISPLAY`).
- `every_shipped_persona_is_self_coherent`: offline coherence for every shipped
  persona (G251 baseline).
- `every_shipped_persona_evaluates_critical_and_high_surfaces`: launches reynard
  for each Firefox-family persona, evaluates the full Firefox catalogue, and
  fails on any High-severity probe error (G252 positive-path live half; negative
  and boundary twins remain in the catalogue unit tests).
- `reynard_matches_stock_firefox_on_high_and_critical_surfaces`: captures stock
  Firefox (via `STOCK_FIREFOX_BIN`) and reynard on the same detector page and
  asserts no High divergences (G254).
- `LiveScorecard` + `GUISE_LIVE_SCORECARD_DIR` write a per-release JSON scorecard
  (G270).
- Skips cleanly when the required environment variables are absent, so CI stays
  green on hosts without a built reynard binary.

### G286 / G287, guise-bridge `/health` + plain-Firefox fallback warning

- Verified `guise-bridge` already exposes `/health` reporting
  `stealth_engine`/`stealth_engine_path`, `webdriver_masked`, and
  `persona_coherence_gate`.
- Unit tests `health_reports_reynard_stealth_posture_when_engine_present` and
  `health_surfaces_degraded_posture_when_plain_firefox` cover both postures and
  assert the plain-Firefox fallback is loud (DEGRADED output + BOT-DETECTABLE
  warning), satisfying G287.

### G299: Dependency CVE scan / trusted-deps hygiene

- Migrated `guise-echo` from unmaintained `rustls-pemfile` to
  `rustls::pki_types::pem::PemObject` (`rustls-pki-types`).
- `cargo tree -p guise-echo -e normal` confirms `rustls-pemfile` is gone.
- `cargo audit` no longer reports `RUSTSEC-2025-0134` for `guise-echo`.
- Added `deny.toml` + `TRUSTED_DEPS.md` documenting accepted transitive
  advisories (`hickory-proto`, `lru`) and the plan to push fixes to the owning
  crates (`scanclient`, `wreq`).
- `cargo deny check` passes for the guise crate.

### G300: MSRV CI job

- Added `.github/workflows/guise-msrv.yml` that pins Rust 1.88 and runs
  `check` + `test` for both `guise` and `guise-echo`.

### G308 / G309: Telemetry-free + egress assertions

- Added `.github/workflows/guise-telemetry-free.yml`.
- The `telemetry-free` job proves the `http-headers`-only feature graph contains
  no `reqwest`, `scanclient`, `hickory`, or `wreq`.
- The `egress-local` job runs the `local_echo_regression` test, which exercises
  guise's TLS/H2 transport against the local `guise-echo` service only.

### G317: Downstream smoke

- `cargo check -p captchaforge` and
  `cargo check --manifest-path software/meridian/Cargo.toml` both pass against
  the local guise changes.

## Remaining blockers (external / cross-crate / risky)

The following tasks cannot be closed safely from the guise crate alone:

- **G272 / G273**, bloat removal (`profile_js` overrides obsoleted by reynard,
  `chrome_tls` paths). `profile_js` is still consumed by captchaforge and by
  guise's own BiDi launch path; `chrome_tls` is still used for H2/structured
  snapshot coherence tests. Removing either without a reynard-source audit and a
  Chromium-consumer decision would break downstream builds.
- **G288 / G290 / G291 / G292** (bridge e2e / captcha-solve / perf / memory).
  E2E shell scripts exist under `guise-bridge/tests/`, but they require a
  reynard/Firefox binary and a display; the perf/memory characterisations have
  not been measured.
- **G293 / G294**, publish guise and subcrates. Requires creating the
  `santhreal/guise` repository and crates.io credentials.
- **G297 / G298**, public-API minimization + semver gate. The public API is
  ~14k lines and heavily used by captchaforge/Meridian; shrinking it requires a
  coordinated cross-crate redesign, not a local refactor.
- **G303–G307**: `guise doctor`, `guise bench`, scorecard regression gate.
  Require a CLI binary surface and CI integration not currently present.
- **G310**, remove `libs/runtime/vendor/rustenium-core`. It is still on the
  build path for `runtime-foxdriver` and captchaforge/guise-bridge.
- **G311 / G312**, reynard engine-major alignment. Requires a reynard source
  checkout and a CI job that builds reynard.
- **G320** (guise v1.0 definition. Milestone contingent on the above ship tasks).

## Validation

- `cargo test -p guise --features browser,http --tests -- --test-threads=1`:
  **938 passed, 0 failed**.
- `cargo test -p guise --features browser,http,tier-b-toml --lib -- --test-threads=1`:
  **993 passed, 0 failed** (includes `config` + hot-reload tests).
- `cargo test -p guise-echo --tests`: **6 passed, 0 failed**.
- `cargo test -p guise --doc`: **12 passed, 0 failed**.
- `cargo bench -p guise --no-run`: compiles cleanly.
- Feature-matrix checks: every single-feature `cargo test -p guise
  --no-default-features --features <flag> --lib` passes for `fingerprint`,
  `human`, `pacing`, `rotation`, `config`, `http-headers`, `reqwest-client`,
  `tls-impersonate`, `browser`, `tier-b-toml`.
