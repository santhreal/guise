# Changelog


## [0.1.5] - 2026-08-07

### Fixed
- **Behavioral noise injector forced Chrome canonical headers and Windows platform hint on unknown user agents.** `NoiseInjector::canonical_profile_for_session` defaulted unrecognized user agents to `StealthProfile::ChromeWindowsStable`, and `platform_hint_from_user_agent` defaulted `Sec-CH-UA-Platform` to `"\"Windows\""`, forging Chrome client hints on non-Chromium/unknown sessions. Fixed: `canonical_profile_for_session` now returns `Option<StealthProfile>` and `platform_hint_from_user_agent` returns `Option<&'static str>`, omitting unresolvable platform hints instead of manufacturing false Windows headers. Locked by unit test `inject_unknown_ua_does_not_forge_windows_platform_hint`.
- **`NavigatorProfile` defaulted corrupted stealth profile names immediately to `ChromeWindowsStable`.** `NavigatorProfile::stealth_profile` used `named_profile(...).unwrap_or(DEFAULT_STEALTH_PROFILE)`, turning non-Chrome profiles with unrecognized names into `ChromeWindowsStable`. Fixed: now attempts `infer_profile_from_user_agent(&self.user_agent)` before defaulting, and exposes `try_stealth_profile(&self) -> Option<StealthProfile>`. Locked by unit test `unrecognized_profile_name_infers_from_user_agent`.
## [0.1.4] - 2026-08-07

### Fixed
- **Tier-B WebGL GPU loader permitted unknown vendor families to bypass platform-coherence validation.** `load_webgl_gpus_from_toml` classified unrecognized vendor strings as `WebGlGpuFamily::Other` and allowed them to pass validation as coherent with `"Win32"`, permitting unclassified GPU vendor strings to enter the persona pool. Fixed: `load_webgl_gpus_from_toml` now rejects `WebGlGpuFamily::Other` with a fail-closed `WebGlGpuLoadError::Invalid` error. Locked by unit test `unknown_gpu_vendor_family_is_rejected_fail_closed`.
- **Crate metadata hygiene.** Updated `Cargo.toml` `authors` field to `Santh <64453045+santhreal@users.noreply.github.com>`.

- **`PersonaPool::restore_snapshot` could hand a restored id out again.** The
  restore path inserted the snapshot's id without advancing the pool's `next_id`
  counter. A snapshot taken from a pool that had handed out more ids than the
  restoring pool carried an id above the counter, and a later `create_session`
  reissued that id, silently overwriting the restored session in the map. The
  restored persona vanished mid-flight and any domain binding to it then pointed
  at an identity the operator never approved. Fixed: restore now moves `next_id`
  past every live id (saturating at `u64::MAX`). Locked by
  `restored_id_is_never_reissued_by_later_sessions` and the `u64::MAX` boundary
  twin `restore_handles_max_id_without_overflow`.
- **`navigator.oscpu` leaked the host OS on a cross-OS persona.** `oscpu` is a
  Firefox-specific, OS-stamped string fingerprinters cross-check against the UA
  platform token, but it was modelled nowhere in `ProfileOverrides` and never
  overridden. Verified live (`tests/surface_truth_live.rs`
  `dump_cross_os_persona_truth`): a `FirefoxWindows` persona on a Linux host
  reported `userAgent="…(Windows NT 10.0; Win64; x64…)"` + `platform="Win32"` +
  `appVersion="5.0 (Windows)"` but `oscpu="Linux x86_64"`: a trivial unmask. The
  probe gate could not catch it because it only exercises the matched
  `FirefoxLinux` persona (oscpu coherent by accident). Fixed: derive oscpu FROM the
  persona UA's OS token (`firefox_oscpu`), so the two surfaces always agree
  (`(X11; Linux x86_64; rv:N)`→`Linux x86_64`, `(Windows NT 10.0; Win64; x64; …)`→
  `Windows NT 10.0; Win64; x64`, `(Macintosh; Intel Mac OS X 10.15; …)`→
  `Intel Mac OS X 10.15`); a malformed UA falls back to an OS-family constant keyed
  on `platform`, never the host (Law 10). A Chromium persona instead DELETES
  `Navigator.prototype.oscpu` (Chrome exposes no oscpu; the Firefox engine's native
  one would be a cross-engine tell). Locked by pure-function unit tests (all UA
  families + fallback), emission tests (Firefox personas pin the UA-coherent oscpu,
  Chromium deletes it), and a live contract (`tests/cross_os_oscpu_live.rs`)
  asserting the Windows and Mac personas report the persona oscpu, never Linux.
- **The masked `gl.getParameter(gl.RENDERER)` leaked the host GPU on a cross-OS
  persona.** The WebGL override spoofed only the `UNMASKED_VENDOR/RENDERER_WEBGL`
  (0x9245/0x9246) params and passed the masked `GL_RENDERER` (0x1F01) through on the
  documented assumption it returns the generic `"Mozilla"`. Firefox 151 changed
  that: it now returns the real (RFP-sanitized) GPU in the masked `RENDERER` (the
  `WEBGL_debug_renderer_info` extension is deprecated in favour of `RENDERER`).
  Verified live (`dump_cross_os_persona_truth`): a `FirefoxWindows` persona reported
  masked `RENDERER="NVIDIA GeForce GTX 980, or similar"` (the Linux host GPU, with
  NO ANGLE/Direct3D signature every real Windows Firefox carries) while the unmasked
  renderer was the spoofed `"ANGLE (Intel … Direct3D11 …)"`: both a host leak and
  an internal masked≠unmasked incoherence. Fixed: pin masked `GL_RENDERER` to the
  persona renderer for cross-OS personas (so masked == unmasked, matching FF 151's
  observed behaviour); `GL_VENDOR` (0x1F00) stays native `"Mozilla"` (still generic
  on FF 151, verified). Matched personas are unchanged (the override is gated on a
  non-empty persona renderer). The rendered PIXELS still originate from the host GPU
A separate cross-process limitation owned by the engine layer. Locked by a live
  contract (`tests/webgl_cross_os_live.rs`) asserting the Windows persona's masked
  renderer carries ANGLE/Direct3D and never `"NVIDIA"`, masked == unmasked, and the
  matched Linux persona is untouched.

- **`navigator.appVersion` was spoofed to a value no real Firefox reports.** The
  per-profile override set `appVersion = userAgent.replace('Mozilla/','')` (the full
  UA string), but modern Firefox FREEZES `navigator.appVersion` to the OS-family
  form: `"5.0 (X11)"` / `"5.0 (Windows)"` / `"5.0 (Macintosh)"`. Verified live
  (`tests/surface_truth_live.rs` `dump_worker_navigator_sweep`): a bare Firefox 151
  on Linux returns `"5.0 (X11)"` in both the window and worker realms, while the
  stealthed window reported the full `"5.0 (X11; Linux x86_64; rv:151.0) Gecko/...
  Firefox/151.0"`, a value that leaks `Firefox/` and `rv:` into appVersion and
  also disagreed with the worker realm (which returns the frozen native form). The
  shared "appVersion non-empty" probe could not catch it (weak check). Fixed: derive
  the frozen OS-family form from the persona `navigator.platform` (correct whether
  matched-host or a cross-OS injection). Added a Firefox-gate probe asserting
  appVersion exactly matches the frozen `5.0 (X11|Windows|Macintosh)` form, an
  emission test pinning each desktop persona's value, and a live contract
  (`tests/navigator_realm_live.rs`) asserting window appVersion is real-FF-shaped
  (no UA leak) AND that window/worker agree on appVersion, userAgent, languages, and
  hardwareConcurrency. A systematic worker-realm navigator sweep confirmed every
  other property is realm-coherent (the `<undef>` worker values match a bare
  Firefox's WorkerNavigator, which genuinely lacks vendor/webdriver/oscpu/etc.).
- **The persona timezone leaked the HOST zone in the Worker realm.** The
  `Intl`/`Date` timezone spoof is a window-realm BiDi preload; a dedicated Worker
  has its own realm the preload never reaches, so `Intl.DateTimeFormat()
  .resolvedOptions().timeZone` and `Date.prototype.getTimezoneOffset()` inside a
  Worker fell back to the host zone. Verified live (`tests/surface_truth_live.rs`
  `dump_worker_timezone_truth`) on a host in `America/Phoenix` with a New_York
  persona: the stealthed page reported `window=America/New_York (offset 240)` but
  `worker=America/Phoenix (offset 420)`: a 180-minute window-vs-worker mismatch
  any detector that spawns a Worker catches. Fixed at the engine level: the persona
  IANA zone is set as the `TZ` env var on the Firefox process, which ICU honors in
  EVERY realm (window + workers), DST-correct. This required a per-process env (not
  the parent's, which would race across concurrent launches with different
  personas), so `launch_profiled_firefox` now uses foxdriver's self-managed
  launcher (foxdriver owns that spawn and gained an additive `FoxBrowserConfig.env`
  field; rustenium's managed launcher hardcodes the spawn env and cannot set it).
  The self-managed path also brings a more robust readiness poll than rustenium's
  fixed 500 ms sleep, and keeps the same fail-closed `user.js` pref-writing. New
  live contract `tests/timezone_live.rs` asserts window and worker agree on the
  persona zone and offset; the stealth gate stays 193/193.
- **Stealth reported window dimensions LARGER than the screen, a physically
  impossible, triple-confirmed tell.** The per-profile layer pinned
  `window.innerWidth`/`outerWidth` to the persona's `screen_width` (1920) while the
  real window stayed the screen-fit size and `screen.*` was deliberately left real.
  Verified live (`tests/surface_truth_live.rs` `dump_geometry_truth`) on a
  1366×768 monitor the stealthed page reported `innerWidth=1920`, producing three
  independent, un-fakeable contradictions: `innerWidth (1920) > screen.width
  (1366)` (a window wider than its own screen), `innerWidth (1920) !=
  document.documentElement.clientWidth (1366)` (the getter lying over the real
  layout viewport), and `matchMedia('(min-width:1920px)') === false` (the CSS
  engine still seeing the real 1366). A JS getter cannot move the real
  layout/matchMedia/screen surfaces, so any pinned size that differs is detected 
  the same matchMedia-mismatch class the layer already avoided for `screen.*`.
  Removed the `innerWidth`/`innerHeight`/`outerWidth`/`outerHeight`/`screenX`/
  `screenY` getters in `profile_js` and the `outerWidth`/`outerHeight`/
  `devicePixelRatio` getters in the generic `FIREFOX_STEALTH_JS`, leaving the real,
  self-consistent geometry (identical to a bare Firefox, which passes every
  matchMedia/clientWidth check). `maxTouchPoints` (a real capability signal not
  contradicted by any layout surface) stays pinned to the persona. The probe
  catalogue MISSED this for the same reason the gate stayed green, it only checked
  `outerWidth >= innerWidth` (true when both were the inflated 1920) and never
  compared to `screen.*`; added five containment/coherence probes
  (`outerWidth/outerHeight/innerWidth/innerHeight <= screen.*` and `innerWidth`
  agrees with `documentElement.clientWidth` within one scrollbar) so the class can
  never regress invisibly. New live contract `tests/geometry_live.rs` asserts the
  shipped disguise is physically coherent; the node-vm oracle now proves no
  geometry getter is installed; gate is 193/193 (was 188/188), 0 critical, 0 drift.
- **Stealth added `navigator.permissions.request` (a method real Firefox lacks) and
  carried a dead `permissions.query` override that would have been a tell.**
  Verified live (`tests/surface_truth_live.rs` `dump_permissions_truth`): a bare
  Firefox reports `'request' in navigator.permissions === false`, but the disguise
  added a `request` method → `true` on the stealthed page, a clean
  bare-vs-stealth divergence. Separately, the `Navigator.prototype.permissions.query`
  override threw an illegal-invocation (the `permissions` getter rejects a
  non-instance `this`) that the `try/catch` swallowed, so it never patched anything
And its name list included Chromium-only permissions (`clipboard-read/write`,
  `accelerometer`, `gyroscope`, `magnetometer`, `ambient-light-sensor`,
  `payment-handler`) that real Firefox REJECTS with `TypeError`; had it worked it
  would have invented `{state:'prompt'}` where real FF throws. Bare FF already
  returns coherent states (`prompt`) for every name it supports, so there was no
  tell to patch. Removed both; kept the `Notification.permission → 'default'`
  normalization (its descriptor is byte-identical to bare FF). New live contract
  `tests/permissions_live.rs` asserts no fabricated `request`, native `query`,
  real per-name states, a Chromium-only name still rejecting, and
  `Notification.permission === 'default'`.
- **The `speechSynthesis` voice-count probe false-Drifted headless/Linux Firefox.**
  The probe asserted `getVoices().length >= 4`, but Firefox sources voices from the
  platform speech engine (speech-dispatcher on Linux), so headless / Linux / CI
  Firefox legitimately reports ZERO voices, and even desktop Firefox returns 0
  synchronously until the async `voiceschanged` event fires. Verified live: the
  BARE, un-stealthed engine returns 0, so the probe Drifted guise's own real
  Firefox. Voice count is an OS/environment fact, not a browser-family truth, so it
  is now dropped for the Firefox gate (CHROMIUM_ONLY_PROBES category 2, no inverse)
  while kept in the Chrome reference catalogue (Chrome bundles voices).
- **The high-resolution-timer probe false-Drifted every privacy-hardened browser.**
  The `performance.now` probe did a tight loop of bare reads and Drifted if it
  "never advanced." But every modern browser coarsens the timer for privacy 
  Firefox's `privacy.reduceTimerPrecision` clamps `performance.now` to ~1ms by
  default: so a tight loop finishes inside one clamp window and reads `0` on a
  perfectly healthy timer. Verified live: a BARE, un-stealthed Firefox returns `0`
  for the tight loop but advances to `1` once real work runs between reads, and
  ticks after ~176 iterations (`tests/surface_truth_live.rs`). Rewrote the probe to
  do work between reads and spin (bounded) until the timer advances, so it measures
  the true granularity: a real timer (even clamped) advances within a few hundred
  iterations → Pass; `0` now means a genuinely frozen/virtualized timer (a real
  sandbox tell) and `-1` still means `performance.now` missing. A structural guard
  (`timer_resolution_js_does_work_between_reads_not_a_tight_loop`) prevents
  regressing to the tight-read form.
- **Stealth fabricated a `window.chrome` own property on Firefox, a self-inflicted
  tell.** `FIREFOX_STEALTH_JS` ran `Object.defineProperty(window, 'chrome', {get:
  () => undefined})`. A real Firefox has NO `chrome` key on `window` at all
  (`'chrome' in window` and `window.hasOwnProperty('chrome')` are both `false` 
  verified live on the bare engine, `tests/surface_truth_live.rs`). Defining a
  getter passed a naive `typeof window.chrome === 'undefined'` check but made
  `'chrome' in window` and `hasOwnProperty('chrome')` **`true`** on the stealthed
  page: a divergence from real Firefox that the descriptor lie-detector caught
  ("window.chrome is own property"). Fabricating the key is strictly worse than
  leaving it absent: this is a Firefox engine, and Chrome personas are disguised at
  the HTTP/TLS layer, not by faking `window.chrome`. Removed the defineProperty (and
  the now-dead iframe `win.chrome` touch); strengthened the `window.chrome absent
  (Firefox)` probe to assert the key is genuinely absent (`!('chrome' in window)`),
  not merely undefined-valued, so the own-property form can never slip through again.
  The lie-detector and the absent probe both pass live.
- **Live oracle tests gave false signals (ran against an insecure origin / a
  non-navigated page / an invalid constructor / a head-less document).** The
  `oracle_live` suite asserted the disguise against `about:blank` (an opaque
  origin where crypto.subtle / StorageManager / serviceWorker / clipboard / caches
  / PushManager are legitimately absent → 14 false "missing surface" Criticals),
  seeded `localStorage` before navigating to a real origin (so seeding stored 0),
  built an analyser with `new AudioContext(1,100,44100)` (a WebIDL TypeError 
  those are `OfflineAudioContext` args), and served `<html><body>` with no `<head>`
  (so `document.head.children.length >= 1` false-Critical'd). Each is corrected so
  the live oracle now validates the real disguise on a secure origin; all five
  `oracle_live` tests pass and the differential oracle confirms two identical stock
  Firefoxes agree on 188/188 surfaces.
- **Async probes never ran: the probe runner discarded Promise results (one
  ProbeError, one silent false-pass).** `run_for`/the differential oracle called
  `page.evaluate(js)`, whose BiDi `awaitPromise` flag is `false`, so any probe
  returning a `Promise` got back an opaque handle instead of its resolved value.
  Two strong-signal probes were affected, both invisible until dogfooded live: the
  **media-codec coherence** probe (`MediaCapabilities.decodingInfo`) deserialized
  to "no ua" and ProbeError'd on every run, a dead probe over a surface anti-bot
  vendors weight heavily; the **Web Worker realm** probe (a `Worker` message
  round-trip) deserialized to `null`, and the **ServiceWorker realm** probe's
  `null` was scored a clean Pass by its "not supported → Pass" branch, a Law-10
  silent false pass. Added `Page::evaluate_await` (BiDi `awaitPromise = true`;
  non-promise results pass through unchanged) in foxdriver and routed the probe
  runner through it. The codec probe now passes against the live engine and the
  Worker realm probe now actually executes, immediately surfacing a real leak
  (below).
- **Persona prefs were silently dropped when launching without a `profile_dir`,
  half-applying the disguise (and able to leak the real IP behind a proxy).**
  `launch_firefox` (foxdriver) writes the assembled `user.js` ONLY when a
  `profile_dir` is set and otherwise discarded every pref, persona UA override,
  `dom.maxHardwareConcurrency`, automation prefs, AND the `network.proxy.*` lines 
  behind a lone `tracing::warn`, returning `Ok(page)` as if fully configured. So a
  caller that omitted `profile_dir` got the JS-preload layer but NOT the engine-pref
  layer: a half-stealthed page, and with a proxy configured a real-IP leak on the
  first navigation. The visible symptom on the stealth gate was a `Worker` realm
  reporting the real `hardwareConcurrency` (the JS override patches only the window
  realm; `dom.maxHardwareConcurrency` is the engine pref that also clamps workers),
  i.e. `hardwareConcurrency 32 vs 8` between window and worker, a trivial detector
  check (spawn a Worker, compare to `window`). Fixed at the source: `launch_firefox`
  now synthesizes a unique temp profile directory whenever `user.js` content exists
  but no `profile_dir` was supplied, and FAILS CLOSED if the prefs cannot be written
  (a detectable/IP-leaking browser must never be returned as `Ok`). With the engine
  pref applied, the worker reports the persona value and the live stealth gate is
  fully clean (188/188, 0 drift, 0 critical). The realm probe's
  `worker_hardware_concurrency_leak_is_drift` test still guards the classifier (a
  genuine window-vs-worker mismatch must still Drift).
- **Worker realm probe false-drifted EVERY real Firefox on `productSub`.** Firefox's
  `WorkerNavigator` does not implement `productSub`, so a real Firefox reports
  window `"20100101"` vs worker `null`: present on the BARE, un-stealthed engine,
  i.e. with no disguise at all. The probe compared the two unconditionally and
  Drifted on it. Fixed to compare `productSub` only when the worker realm actually
  exposes it (a genuine both-present-but-different spoof is still caught; an absent
  worker value is a `WorkerNavigator` API fact, not a coherence tell).
- **Removed the ServiceWorker realm probe, it could never run.** A ServiceWorker
  can only be registered from a same-origin HTTP(S) script URL; the probe used a
  `blob:` URL, which the platform rejects ("Invalid scope trying to resolve ./
  with base URL blob:…", confirmed live), unlike a dedicated `Worker` which accepts
  blob URLs. A generic probe cannot serve a SW script on an arbitrary origin, so
  the realm is unreachable; the probe threw on every secure origin and silently
  Passed via its `null` branch. The Web Worker realm probe covers the same
  window-vs-worker navigator coherence and actually runs, so the dead SW probe is
  dropped rather than faked.
- **The live probe gate false-Critical'd guise's OWN Firefox on 6 engine-
  conditional surfaces (WebGPU ×5 + Document Picture-in-Picture).** Dogfooding the
  runtime probe catalogue against guise's own headless Firefox 151 (the
  `probe_live` gate) surfaced 6 Criticals on a perfectly clean browser. Ground
  truth (`tests/surface_truth_live.rs`, a live diagnostic on a secure origin,
  identical for bare and stealthed engines): (1) the five WebGPU presence probes
  (`navigator.gpu`, `requestAdapter`, `GPUAdapter`, `GPUBufferUsage`,
  `getPreferredCanvasFormat`) use `classify_must_be_true`, but WebGPU is OFF by
  default on Firefox Linux/macOS and in headless (default-ON only on Firefox
  Windows 141+): `navigator.gpu` is genuinely `undefined` on the live engine even
  in a secure context, so every probe Critical'd a real Firefox. (2) The
  `DocumentPictureInPicture absent (Firefox)` *inverse* probe (added last cycle
  from a name list, never live-verified) was simply wrong: Firefox 151 ships the
  Document Picture-in-Picture API in a secure context (`documentPictureInPicture
  === "object"`). Fixed by treating both as **engine-conditional** surfaces dropped
  for the Firefox gate WITHOUT an inverse (asserting presence OR absence would
  false-Critical some real Firefox), a new category 2 in `CHROMIUM_ONLY_PROBES` 
  while keeping them in the Chrome reference catalogue (modern desktop Chrome
  exposes the API surface). Removed the false inverse probe and the stale
  `documentPictureInPicture` entry from the structural guard's Chromium-only token
  list. The live gate now reads 0 stealthed Criticals; a new unit test
  (`engine_conditional_surfaces_dropped_for_firefox_kept_for_chrome`) pins the
  family-aware drop so neither a presence nor an absence assertion for these
  surfaces can leak back into the Firefox catalogue.
- **Typed newlines produced a Numpad Enter, and telemetry logged the raw control
  byte instead of the DOM key (two keystroke tells).** `HumanTyper::type_text`
  special-cased only Backspace and otherwise pushed the planner's raw character
  straight to the driver and into the telemetry stream. Two problems, both proven
  live (`tests/shift_key_live.rs`): (1) the BiDi driver normalises `"\n"` to its
  named `"Enter"`, which resolves to WebDriver code point **U+E007 (Numpad
  Enter)**, so every newline a human typed registered as `code === "NumpadEnter"`,
  a key real typists essentially never use to enter text. (2) The telemetry
  `KeyDown`/`KeyUp` `key` field recorded the raw `"\n"` even though the actual DOM
  event reported `key === "Enter"`: the G170 behavioral stream consumed by
  captchaforge disagreed with what the page saw. Fixed: a new
  `key_to_bidi_dispatch_key` sends the raw **U+E006 (RETURN)** code point for a
  newline, which Gecko renders as the *main* Enter (`code === "Enter"`), while the
  telemetry `key` is derived from `key_to_key_value` so it matches the DOM
  (`"Enter"`/`"Tab"`/`"Backspace"`/printable). The live contract test types
  `"a\tb\nc"` and asserts the newline keydown is `key:"Enter" code:"Enter"` (not
  NumpadEnter), Tab is `key:"Tab" code:"Tab"`, and no raw control char ever
  appears as a `KeyboardEvent.key`; an offline unit test pins the dispatch mapping
  (newline → single-code-point U+E006, never the named `"Enter"`).
- **Uppercase letters and shifted symbols were typed with NO Shift key (keystroke
  tell).** `HumanTyper::type_text` sent every character as its bare value (`"H"`,
  `"!"`) plus only a timing `shift_delay`: never a Shift key action. rustenium's
  BiDi bridge passes a single-char value straight through and Gecko does NOT
  synthesise a modifier, so (proven live, `tests/shift_key_live.rs`) the keydown
  for an uppercase/symbol carried `shiftKey === false` with `getModifierState('Shift')
  === false` and no preceding `ShiftLeft`: physically impossible for real typed
  input and a direct keystroke-dynamics tell. Fixed: a shifted character (any
  `needs_shift(ch)`: ASCII uppercase or a shifted-symbol) is now wrapped in a
  genuine `Shift` keydown (with a human Shift-to-key latency) and keyup around the
  character, mirrored into the telemetry stream as `ShiftLeft` events. The live
  contract test asserts typing `"Hi!"` yields value `"Hi!"` with `H`→`KeyH`/`!`→
  `Digit1` both carrying `shiftKey===true`, lowercase `i` unshifted, and a real
  `ShiftLeft` keydown present.
- **Per-keystroke timing was uniform-within-envelope (distribution-shape tell).**
  Every inter-key gap and key-hold was drawn with `rng.gen_range(lo..=hi)`: a flat
  box with equal density across the whole envelope and hard edges, putting ~33% of
  mass in the central third and a real, repeated fraction of samples at the rare
  extremes. A keystroke-dynamics classifier (the dominant behavioural biometric)
  trains on exactly this latency *shape*; a human's per-bigram latency is unimodal,
  not flat. Fixed: all gap/hold draws now go through `center_weighted` (symmetric
  triangular = rounded mean of two uniform draws), which peaks at the envelope
  centre and tapers to ~zero density at both bounds while staying strictly within
  `[lo, hi]` (so every envelope-bounds contract still holds). The deliberate
  thinking-pause outlier stays uniform (it widens between-bigram spread, which the
  CV floor needs). Proven by `center_weighted_peaks_at_envelope_center_not_flat`
  (central-third mass > 0.45 over 40k draws: ~0.56 triangular, fails at ~0.33 for
  a regression back to `gen_range`) and the existing `generated_typing_rhythm_clears_human_cv_floor`
  still holds (between-bigram spread dominates CV).
- **Firefox probe gate false-Critical'd on ~11 Chromium-only surfaces (half-wired
  family-awareness).** `probes_for(Firefox)` drops the surfaces listed in
  `CHROMIUM_ONLY_PROBES` and replaces them with Gecko-truth inverses, but the
  EXTENDED catalogue (`catalogue_extended.rs`) added Blink-only presence probes
  (`performance.memory`/jsHeapSizeLimit, `navigator.keyboard`,
  `navigator.presentation`, `navigator.scheduling`, `navigator.setAppBadge`/
  `clearAppBadge`, `documentPictureInPicture`, `EyeDropper`,
  `AbsoluteOrientationSensor`, plus `BarcodeDetector`/`FaceDetector`) that were
  never registered there. Each uses `classify_must_be_true`, which returns
  **Critical** when the surface is absent, and a real Gecko build (guise's OWN
  live Firefox/reynard browser) exposes none of them. So every Firefox probe run
  reported a flood of false Criticals, which can never clear and bury real tells.
  The guarding test was vacuous: it only re-checked names already in
  `CHROMIUM_ONLY_PROBES` against itself, so a surface never added there passed
  silently. Fixed: registered the 9 stable Blink-only surfaces as Chromium-only
  (dropped for Firefox) with inverse `… absent (Firefox)` assertions for 8 of them
  (a Firefox persona that LEAKS a Blink API is a genuine Chromium-engine tell), and
  added a structural regression guard
  (`firefox_catalogue_has_no_chromium_only_presence_probe`) that inspects the actual
  Firefox catalogue, any `classify_must_be_true` probe whose JS references a known
  Blink-only global now fails the build, catching future leaks the name-list cannot.
- **Removed two probes that false-Critical'd legitimate desktop browsers
  (BarcodeDetector / FaceDetector).** The Shape Detection API has no stable
  real-browser truth to assert: absent on all Firefox, absent on Chrome
  Windows/Linux desktop (no platform backend), present only on Chrome
  Android/ChromeOS/macOS, and FaceDetector is flag-gated everywhere. A
  `classify_must_be_true` presence check therefore reported Critical on legitimate
  Chrome Windows/Linux AND every Firefox, a false tell on BOTH gates. The two
  probes are removed (the surface carries no honest assertion); the catalogue stays
  well above the `PROBE_COUNT_FLOOR`.
- **CreepJS trust-score canvas-instability penalty inspected the wrong channel.**
  The `creepjs.trust_score` probe's inline canvas check (`creepjs.rs`) compared two
  `getImageData` reads with a loop starting at `i = 3` stepping by 4, i.e. it
  examined ONLY the alpha channel. A canvas farble (guise's, and every naive one)
  perturbs the **RGB** channels and leaves alpha untouched, and a solid fill holds
  alpha constant, so the documented "unstable canvas (per-read rand) −15" penalty
  could never fire for the per-read RGB-randomization tell it exists to catch: a
  bot using a naive per-read RGB randomizer scored 15 points too high (enough to
  cross Drift→Pass or Critical→Drift). Now compares R/G/B (`a[i],a[i+1],a[i+2]`)
  and excludes the deliberately-untouched alpha, matching the standalone
  session-stability probe. Proven by a new Node oracle
  (`tests/probe_js_node_oracle.rs`) that drives the real catalogue JS with a
  per-read-RGB-randomizing canvas and asserts the score drops by exactly 15, a
  diff of 0 (the alpha-only bug) fails it.
- **Worklet-presence probe constructed (and leaked) an `AudioContext`.** The
  `realm: AudioWorklet / PaintWorklet presence` probe read `(new AudioContext())
  .audioWorklet` to test for AudioWorklet support, instantiating an audio context
  it never closed, an observable side effect inside the page being kept clean, and
  (since the probe is not wrapped in try/catch) a hard ProbeError once the page hit
  the browser's per-document AudioContext cap (~6 in Chrome) or an autoplay/gesture
  policy. The accessor lives on `AudioContext.prototype` (inherited from
  `BaseAudioContext`), so presence is now read with `'audioWorklet' in
  AudioContext.prototype`, identical boolean, zero side effects, no throw path. A
  Node oracle asserts the probe reports `audioWorklet:true` while never invoking the
  `AudioContext` constructor (call counter stays 0; the old code made it 1).
- **[CRITICAL] Evasion noise was dead at runtime (ASI IIFE concatenation).**
  `evasion_js_source` joined its per-surface noise IIFEs with a bare `"\n"`. Two
  adjacent IIFEs (`})()` ⏎ `(function(){…})()`) are parsed by JavaScript's
  automatic-semicolon-insertion rules as `})()(function…)`: a *call* of the first
  IIFE's `undefined` return, which throws `TypeError` and aborts the entire
  preload script. In the shipped default config (canvas + audio + font + WebGL)
  only the first IIFE (canvas) ran; **all audio, font, and WebGL fingerprint
  evasion silently never applied** in a real browser. Every unit test passed
  because none executed the assembled script. Now joined with `;\n` plus a
  trailing `;`. Proven by a new Node behavioral oracle.
- **Canvas `getImageData` was undefended (recall hole).** Noise was applied only
  in the `toDataURL`/`toBlob` serialization path; a fingerprinter reading pixels
  via `CanvasRenderingContext2D.getImageData`: the primary canvas-fingerprint
  extraction method, received the true, un-noised buffer. `getImageData` is now
  farbled at the source with a deterministic per-pixel perturbation keyed on
  absolute coordinates, so it is session-stable, coherent with the serialization
  path, and unlinkable across sessions. The main-thread `OffscreenCanvas`
  (`OffscreenCanvasRenderingContext2D.getImageData`) bypass is covered too.
- **Canvas `measureText` font fingerprint was undefended (recall hole).** The
  dominant font-detection technique (render each candidate font, compare text
  width) read true metrics. `measureText` now scales every `TextMetrics` number
  by a per-session factor applied uniformly. O(1), so no timing tell, which
  perturbs the exact-width fingerprint while preserving font-presence detection
  (equality/ordering survive scaling) and text layout (sub-0.1px shift). This is
  now the `font_noise` axis, replacing the old `FontFaceSet.forEach` enumeration
  skip: which only touched page-loaded `@font-face` faces (not the installed
  system fonts a fingerprinter probes) and made the iterated count disagree with
  `document.fonts.size`, a guise-introduced coherence tell (now removed).
- **Audio `OfflineAudioContext` fingerprint was undefended (recall hole).** Noise
  was applied only to a per-instance `getFloatFrequencyData` created via
  `AudioContext.createAnalyser` (which also added an own-property tell). The
  canonical audio fingerprint: `OfflineAudioContext` render read via
  `AudioBuffer.getChannelData`: was untouched. Audio farble now patches
  `AudioBuffer.prototype.getChannelData` (idempotent per buffer) and
  `AnalyserNode.prototype.{getFloatFrequencyData,getFloatTimeDomainData}` at the
  prototype level (covering every construction route with no own-property tell).
- **Session-noise probes rewarded a detection tell.** The canvas/audio
  "randomized (session strategy)" probes treated per-read *instability*
  (`read() !== read()`) as a Pass, but the classifier's own docs (and `creepjs`)
  note that per-read variation is itself a tamper tell, and a correct
  deterministic farble never produces it. Probes renamed to "… session-stable (no
  per-read tell)" and `classify_session_noise` inverted: stable = Pass, unstable =
  Drift: consistent with the CreepJS scoring model.
- **`KeyboardEvent.code` was empty for every punctuation/symbol key.**
  `key_to_code` returned `""` for `- _ = + [ ] \ ; ' , . / ` { } | : " < > ? ~`
  and all shifted number-row symbols (`! @ # … )`). A real `KeyboardEvent.code`
  is the *physical* key and is never empty, an empty `code` on a `keydown` is
  itself a synthetic-input tell, and it violated the module's own contract
  ("maps logical characters to QWERTY `code` values so `code` vs `key` stays
  coherent"). The value flows live into `HumanTyper` telemetry (feeding the
  behavioral scorers, G170) and the public `plan_key_events`/`plan_typed_text`
  API. Now maps the complete US-QWERTY physical layout: shifted symbols report
  their unshifted physical key (`!` → `Digit1`, `?` → `Slash`, `_` → `Minus`);
  characters with no US-QWERTY key (non-ASCII/IME) return `""` to match the
  empty `code` real browsers report for composed input, never a fabricated
  multi-byte `code`. Added `key_to_key_value` so synthesized Enter/Tab/Backspace
  report their DOM key name (`"Enter"`, not the raw `"\n"`).
- **`HumanScroller` mouse-wheel persona emitted trackpad-shaped deltas.** The
  default `WheelDevice::MouseWheel` persona recorded `deltaMode=1` (line mode)
  but `execute_flick` always emitted a smooth friction-decay stream (80, 57,
  41… px), the signature of a *trackpad* (pixel mode), not a wheel, which emits
  discrete ~equal detents. `WheelDevice::delta_y` (the per-notch magnitude model)
  was dead test-only code, and `wheel.rs` falsely documented that the dispatch
  layer used it. The step generator now branches on the device's `deltaMode`:
  line-mode devices emit quantized ~`step_px` notches via `delta_y` at detent
  cadence (45–120 ms), pixel-mode devices keep the smooth momentum model at
  ~frame rate, each coherent with its recorded `deltaMode`. Wires the formerly
  dead `delta_y` into the live path; doc corrected.
- **Stealth `outerWidth`/`outerHeight` went stale after a resize.** The generic
  stealth JS captured `innerWidth`/`innerHeight` once at install time and
  returned the captured value from the `outerWidth`/`outerHeight` getters, so
  after a window resize they reported the ORIGINAL viewport, and could read
  *smaller* than the new `innerWidth` (`outerWidth < innerWidth` is physically
  impossible), a resize-and-recheck tell. The getters now read
  `innerWidth`/`innerHeight` live, keeping the window-chrome offset constant.
  Proven by a new Node oracle that simulates a resize (the string-match tests
  could not see it).
- **PCFG mouse trajectories had no trusted delivery path.** The
  `behavioral_grammar` PCFG produces sophisticated multi-inflection
  human-mouse trajectories specifically to defeat shape analysis, but its only
  renderer, `render_to_js`, dispatched them via DOM
  `dispatchEvent(new MouseEvent('mousemove', …))`: every event arrives
  `isTrusted === false`, the cheapest bot tell, which lets a detector skip shape
  analysis entirely. (`render_to_js`'s doc even falsely claimed it produced "CDP
  `Input.dispatchMouseEvent`", it never did; a DOM-dispatched event can never be
  trusted.) The whole model was also unwired: `render_to_js` had no production
  caller. Added `HumanMouse::follow_trajectory`, which plays a `Trajectory`
  through the TRUSTED BiDi pointer path (`move_mouse_to` per sample, `click_at`
  for the terminal click, honoring per-sample `dt_ms`), so the trajectory model
  is finally usable for stealth. `render_to_js`'s doc now loudly states its
  events are untrusted and is scoped to test/instrumentation use, pointing to
  `follow_trajectory` for evasion. A Node oracle executes `render_to_js` output
  and asserts every dispatched event is `isTrusted === false`, locking the
  distinction.
- **`touch_swipe`/`pointer_jitter` reset the cursor to the origin every
  sub-step.** Both gestures called `page.mouse_move_human(fixed_origin, …, x, y)`
  inside their loop, but `mouse_move_human` *forcibly resets* the cursor to its
  first argument before moving (foxdriver `set_last_position`). So `touch_swipe`
  teleported back to `(x0, y0)` and re-curved from there on each of 25 steps. 25
  trajectories fanning out from the start instead of one continuous drag, and
  `pointer_jitter` snapped back to the centre between every tremor point, turning
  a smooth wander into a star burst through the centre. `touch_swipe` now threads
  the previous point so the drag is continuous (and stays on the same
  button-held pointer source as `mouse_down`); `pointer_jitter` now issues one
  trusted `move_mouse_to` per absolute Lissajous point. Extracted a pure,
  unit-tested `swipe_points` (ease-out, exact landing, monotonic) so the swipe
  geometry is locked.
- **No contract tied HTTP `Accept-Language` to JS `navigator.languages`.** The
  two are independent profile fields (facts vs overrides) for the same logical
  fingerprint; all shipped profiles happen to be `en-US`, but nothing enforced
  coherence, so a future non-English persona or an `accept_language` data slip
  could silently ship the classic Accept-Language-vs-`navigator.languages`
  cross-layer mismatch. Added an all-profile contract test asserting the bare tag
  lists are equal (q-weights dropped) for every shipped profile.
- **Coherence gate missed the Direct3D-renderer-on-non-Windows tell.** The
  persona validator rejected an Apple GPU on a non-Apple platform but had no
  mirror for the other direction: a `Direct3D`/`D3D11` renderer is the Windows
  ANGLE backend and physically exists only on Windows, yet a `MacIntel`/`Linux`
  persona carrying `"ANGLE (NVIDIA, … Direct3D11 …)"` passed validation. The gate
  now rejects a Direct3D/D3D11 renderer on any non-`Win32` platform (macOS uses
  Metal, Linux uses Mesa/OpenGL). Every shipped Direct3D persona is Win32, so the
  all-persona sweep still passes; a new negative test grafts a Direct3D renderer
  onto a macOS persona and asserts rejection.
- **WebGL spoof leaked the GPU string on the MASKED `GL_VENDOR`/`GL_RENDERER`.**
  For a cross-OS persona, `profile_js` overrode `getParameter` to return the
  persona's (unmasked-style) GPU strings, e.g. `"Google Inc. (Intel)"`,
  `"ANGLE (NVIDIA, …)"`: for BOTH the unmasked params (`UNMASKED_VENDOR_WEBGL`
  0x9245 / `UNMASKED_RENDERER_WEBGL` 0x9246) AND the masked `GL_VENDOR` (0x1F00) /
  `GL_RENDERER` (0x1F01). But every real browser returns a *generic engine* value
  for the masked params (Firefox: `"Mozilla"`/`"Mozilla"`); only the unmasked
  params carry the GPU. So `gl.getParameter(gl.VENDOR)` reported the GPU string
  where every real Firefox reports `"Mozilla"`: a coherence tell. The override
  now touches ONLY the unmasked params and lets the masked ones pass through to
  the real Gecko value (the live path runs Firefox-family personas only, G092).
  The profile_js Node oracle now asserts the masked/unmasked split for every
  cross-OS persona (masked passes through; unmasked equals the persona GPU).
- **`user.js` builder only escaped quotes, a newline silently dropped the
  persona.** `build_user_js` escaped `"` but not `\`, newline, CR, or tab in the
  UA / platform / languages override values (all reachable via the public
  `ProfileOverrides`). A newline split the `user_pref("general.useragent.override",
  …)` call across physical lines, so Firefox failed to parse it and the persona UA
  override was silently dropped, the browser then served its REAL UA while the JS
  layer claimed the persona's, the exact JS-vs-HTTP mismatch this layer prevents
  (a Law-10 silent fallback). A prior test even asserted the broken literal-newline
  output as "documented behaviour" (Law 9). Added `escape_pref_value` (backslash
  first, then `"`, `\n`, `\r`, `\t`); every override value now produces one valid
  pref line. The old test now asserts correct escaping, plus new tests for
  backslash/control chars and a hostile newline+quote override that must not break
  the pref-file line structure or inject a separate pref.
- **`userAgentData`/`deviceMemory` were created non-enumerable (a Chromium-persona
  tell).** `profile_js` defines its navigator getters with `enumerable` omitted.
  For attributes that already exist on a real Firefox `Navigator.prototype`
  (`userAgent`, `platform`, …) redefinition *preserves* the native
  `enumerable:true`, so those are fine, but `userAgentData` and `deviceMemory`
  are Chromium-only and CREATED fresh on the Firefox engine for a Chromium
  persona, where an omitted `enumerable` defaults to `false`. Real Chrome exposes
  both as `enumerable:true` WebIDL attributes, so
  `getOwnPropertyDescriptor(Navigator.prototype,'userAgentData').enumerable` read
  `false`: a tell on exactly the cross-engine persona that most needs to pass.
  Both are now created with `enumerable: true`. The profile_js Node oracle now
  asserts the descriptor enumerability for every Chromium persona.
- **Intl spoof broke `constructor` identity (a tampering tell).** The locale/zone
  spoof replaces `Intl.DateTimeFormat` (and `NumberFormat`, `Collator`,
  `RelativeTimeFormat`, `PluralRules`, `ListFormat`) with a wrapper sharing the
  original `prototype`, but left `prototype.constructor` pointing at the captured
  original. So `Intl.DateTimeFormat.prototype.constructor === Intl.DateTimeFormat`
  and `new Intl.DateTimeFormat().constructor === Intl.DateTimeFormat` both
  returned `false`: `true` in every real engine, a trivial one-line tell that
  the constructor had been swapped. Each wrapper now repoints the shared
  prototype's `constructor` at itself with the native descriptor (writable,
  non-enumerable, configurable). A new Node oracle asserts the invariant for all
  six constructors (instance- and prototype-level) and that persona injection
  still works. This was the only constructor-wrapper site in the emitted JS.
- **`click_element` recorded no click telemetry.** Unlike `HumanMouse::click`,
  the element-targeted `click_element` issued its `mouse_down`/`mouse_up` without
  recording `PointerDown`/`PointerUp` to the behavioral telemetry, so a scorer
  attached via `with_telemetry` saw the approach moves but not the click on the
  primary element-click path (a G170 completeness gap). It now records the
  press/release pair with the persona's active/hover pressures, matching
  `HumanMouse::click`.

### Changed

- **Live mouse driver now uses the real-human trace corpus, not a cubic Bézier.**
  `HumanMouse::move_to` generated its trajectory from a single cubic Bézier, the
  exact "constant curvature signature" `mouse.rs`'s own docs say ML behavioural
  classifiers flag, and the real-trace `MouseSampler` corpus (built to replace it)
  was wired to NOTHING but its own tests. The corpus could not drive a click
  because `MouseSampler::sample` random-walks its endpoint up to ~100px off-target
  (per-step jitter never compensated). Added `MouseSampler::resampled_path`, which
  affine-maps a real trace's normalised cumulative shape onto the move and lands
  EXACTLY on the target, and pointed the live driver at it. Timing, easing,
  overshoot, telemetry, and trusted BiDi dispatch are unchanged; only the geometry
  source moved from synthetic Bézier to real-human curvature. Removed the now-dead
  `cubic_bezier` helper.

### Fixed

- **`HumanScroller` scrolled via untrusted `window.scrollBy` (no wheel event).**
  Every flick/overshoot routed through `page.evaluate("window.scrollBy(…)")`, a
  programmatic scroll that moves the page while firing NO `wheel` event, a script
  listening for `wheel` sees the page scroll with zero wheel input, the same
  `isTrusted`-class tell the mouse path routes around. `scroll_by` now uses the
  trusted BiDi wheel input (`Page::scroll` → `mouse().wheel`), emitting a real
  `wheel` event. Also corrected scroll.rs's module docs, which falsely claimed
  `behavior::scroll_realistic` routes through `HumanScroller` (it delegates to
  foxdriver's `Page::scroll_realistic`; `HumanScroller` is the richer engine
  offered to callers that drive a `Page` directly).
- **`MouseSampler::sample` endpoint drift.** Per-step `±2px` jitter accumulated, so
  the trace ended up to ~100px off the requested target despite the documented
  "hits the requested end coordinate exactly." The final step now compensates the
  accumulated jitter, landing the trace exactly on target (the test that tolerated
  ±100px drift now asserts exact landing).

### Added

- **Canvas/audio farble behavioral oracle.** New
  `tests/evasion_farble_node_oracle.rs` executes the emitted evasion JS under
  Node.js against stub DOM prototypes and asserts the load-bearing properties:
  `getImageData`/`getChannelData` farbled, session-stable, coherent across
  regions/paths, audio idempotency (no double-perturb on re-read), no
  own-property tell, native `toString`, and that the full multi-surface source
  evaluates without aborting (the ASI regression).
- **Three must-cover runtime probes.** `RTCPeerConnection.createOffer`,
  `navigator.mediaDevices.getUserMedia`, and `AnalyserNode.getFloatFrequencyData`
  gained sound presence probes + inventory bridge links, shrinking the honest
  `uncovered_must_cover` gap to just `navigator.gpu.requestAdapter`.
- **Stealth `outerWidth`/`outerHeight` live-tracking oracle.** A Node behavioral
  unit test executes the real stealth IIFE against a `window` stub, simulates a
  resize, and asserts the outer dimensions track `innerWidth`/`innerHeight` live
  (the chrome offset stays constant, never `outerWidth < innerWidth`) and that
  the getter still reports `[native code]`. Verified to fail on the prior
  capture-once code.
- **Keyboard `code` coverage tests.** Every printable-ASCII key asserts a
  non-empty physical `code`; symbol and shifted-number-row keys assert their
  exact physical key (`!`→`Digit1`, `?`→`Slash`, …); off-layout characters
  assert an empty (never fabricated) `code`.
- **Wheel-device delta-shape tests.** Assert the mouse-wheel persona emits
  uniform coarse ~`step_px` notches (not a decay), the trackpad persona emits a
  smooth non-notch stream, notch count scales with distance, notches follow
  scroll direction, and a sub-notch distance still emits one whole notch.

### Security / Dependencies

- **CVE-scan hygiene (G299).** Migrated `guise-echo` from the unmaintained
  `rustls-pemfile` crate to `rustls::pki_types::pem::PemObject` (via
  `rustls-pki-types`). `rustls-pemfile` no longer appears in the `guise-echo`
  dependency tree, resolving `RUSTSEC-2025-0134` for that crate. Added
  `deny.toml` and `TRUSTED_DEPS.md`; `cargo deny check` passes.

### Added

- **Live-detector acceptance suite (G251 / G252 / G254 / G270).** New
  `tests/live_detector_suite.rs` provides a gated, opt-in suite: offline
  coherence for every shipped persona, per-persona live catalogue evaluation
  against reynard, stock-Firefox differential comparison, and a JSON scorecard
  written to `GUISE_LIVE_SCORECARD_DIR`.
- **Telemetry-free + egress assertions (G308 / G309).** New
  `.github/workflows/guise-telemetry-free.yml` proves the `http-headers`-only
  feature graph contains no `reqwest`, `scanclient`, `hickory`, or `wreq`, and
  runs the local `guise-echo` regression to pin intended egress to localhost.
- **MSRV CI job (G300).** New `.github/workflows/guise-msrv.yml` pins Rust 1.88
  and runs `check` + `test` for `guise` and `guise-echo`.
- **Downstream smoke (G317).** Verified `captchaforge` and `meridian` still
  build against the local guise changes.

- **Catalogue completeness critic (G213 / G215).** New `probe::completeness`
  module adds a curated `KNOWN_FINGERPRINTER_CHECKS` list and
  `coverage_report(browser)`. It matches known CreepJS/fpcollect/sannysoft-style
  checks against the runtime catalogue, reports coverage percentage, and flags
  gaps: with per-browser applicability so Chromium-only checks are not false
  Firefox gaps. CI asserts all `Critical`-level checks are covered.
- **Unified live oracle suite (G209 / G210).** Replaced
  `tests/differential_oracle.rs`, `tests/headful_truth.rs`,
  `tests/headless_tells.rs`, and `tests/stealth_core_tells.rs` with a single
  `tests/oracle_live.rs`. The suite uses the shared probe catalogue
  (`diff_pages` / `run_for`) for soundness, residual-tell visibility,
  automation-tell assertions, and optional headful/headless diagnostics,
  removing duplicated bespoke JS checks across the four former files.
- **Production drift detector with auto-bisect (G207 / G208).** New `probe::drift`
  module adds `DriftDetector`, `DriftSnapshot`, `DriftEvent`, `BisectReport`, and
  `PersonaContext`. The detector is anchored to a known-good reference snapshot and
  compares a baseline against a current full-stack capture, emitting new vs
  recovered vs still-diverging surfaces and a combined scorecard. A configurable
  severity threshold (`High` default) controls when an alert fires. The auto-bisect
  report attributes new drift to the changed layer (`Js` / `Transport` /
  `Behavioral`), the persona override field(s) involved (via the G119 bridge), or
  engine-level surfaces, and surfaces `PersonaContext` rotations as the primary
  suspect when the profile/seed/UA/platform/TLS/OS-stack changed.
- **Catalogue expansion to 200+ surfaces (G183).** New `probe::catalogue_extended`
  module adds 35 probes across WebGPU (`navigator.gpu.requestAdapter` as High
  severity), Permissions API, Intl APIs, performance/memory, navigator/device
  extensions, storage, sensors, and lifecycle surfaces. The family-aware
  catalogue now contains **201** unique probes; `PROBE_COUNT_FLOOR` is raised
  to 200 to prevent silent regressions.
- **BiDi-specific automation-tell probes (G199 / R015).** New `probe::bidi_tells`
  module adds six probes for WebDriver BiDi footprints:
  `window.__webdriver_evaluate`, `window.__webdriver_script_fn`,
  `window.__webdriver_script_function`, `Error.stack` markers for
  `webdriver_evaluate` and `bidi_script`, and inherited `navigator.webdriver`.
  Wired into the family-aware catalogue so every run checks for BiDi transport
  leaks alongside the existing CDP/automation-global probes.
- **Offline oracle fixture for deterministic CI (G190).** `probe::oracle` now
  separates capture (`capture_page`) from diffing (`diff_captures`). A
  `Capture` is a serializable set of probe results, so the oracle can run
  offline against a captured-page fixture with no live browser. Added
  `probe::fixture` with a synthetic stock-Firefox vs JS-disguise fixture and
  `tests/oracle_fixture.rs` to regression-lock report rendering, scorecard
  serialization, and critical-surface prioritization in CI.
- **Oracle scorecard schema + shared taxonomy + calibrated benchmark impact
  (G181 / G184 / G195 / G196 / G217).** New `probe::scorecard` module defines
  a versioned, serializable `Scorecard` that anchors every divergence to the
  shared `fingerprint::surface` inventory taxonomy. `Divergence` now carries an
  optional `surface_id` bridged from the catalogue probe via
  `surface_coverage::surface_id_for_probe`. Weights are calibrated from the
  inventory's `Criticality` (`Critical = 100`, `High = 40`, `Medium = 10`,
  `Low = 2`) with a `Severity` fallback for unbridged probes. Benchmark points
  equal weight, giving a direct scoreboard cost per divergence, and
  `Scorecard::prioritized_fixes()` orders fixes by lost points with engine-level
  tells ranked above persona-intended ones. This is the cross-crate contract for
  reynard CI, captchaforge gating, and future `guise bench` scorecards.
- **Three-way oracle comparison: stock vs reynard vs JS-disguise (G182).**
  Added `three_way_compare`, `ThreeWayReport`, and `render_three_way` to
  `probe::oracle`. The report classifies each surface as an engine win
  (stock == reynard != disguise), a JS win (stock == disguise != reynard),
  or everyone loses (all differ), making visible where the patched browser
  engine outperforms JS spoofing. Unit tests cover all three buckets plus
  agreement/error handling; `tests/oracle_fixture.rs` proves the engine is
  strictly closer to stock than the JS disguise on the synthetic fixture.
- **CreepJS trust-score probe (G192).** New `probe::creepjs` module adds a
  catalogue probe that computes a CreepJS-style trust score (0–100) from
  live integrity checks: `navigator.webdriver`, plugin/MIME richness, WebGL
  renderer, timezone, automation globals, error-stack markers, and more.
  The classifier mirrors CreepJS thresholds (≥80 Pass, 40–79 Drift, <40
  Critical) so the oracle exposes a single detector-meaningful surface.
- **Network-layer oracle surfaces (G202/G203).** New `probe::transport`
  module (`http-headers` feature) exposes transport fingerprints as oracle
  surfaces: `transport.ja3`, `transport.ja4`, `transport.ja4t`,
  `transport.p0f_signature`, `transport.h2_akamai`, `transport.h2_peet`, and
  `transport.alpn`. Values are computed from the same persona bundle as the
  JS layer so the oracle can diff TLS/H2/TCP coherence.
- **Behavioral + full-stack oracle (G204–G206).** New `probe::behavioral`
  module samples guise's human typing model deterministically from a seed and
  exposes `behavioral.typing_avg_hold_ms`, `behavioral.typing_avg_gap_ms`,
  `behavioral.typing_typo_count`, `behavioral.delays_are_distributed`, and
  `behavioral.realism_score`. `probe::oracle` now provides `FullStackReport`,
  combining JS, transport, and behavioral layer diffs with a
  `combined_scorecard` for one CI regression gate.
- **Gap-to-probe conversion (G211).** The Firefox Client-Hints gap is now a
  runtime catalogue probe (`navigator.userAgentData absent or brands empty
  (Firefox)`), and the hardware-concurrency gap is continuously guarded by the
  existing `navigator.hardwareConcurrency` probe. Source-level gaps that are
  not browser surfaces remain pinned by `tests/gap.rs`.
- **Adversarial suite growth (G212).** `tests/adversarial.rs` now covers the
  new oracle surfaces: extreme behavioral seeds, Safari transport capture
  without a measured H2 target, and graceful handling of mismatched labels in
  `full_stack_compare`.
- **Severity auto-tuning (G216).** New `SeverityTuner` in `probe::scorecard`
  lets a real detector/WAF verdict feed back into the scorecard: surfaces that
  contributed to a block get a capped weight boost, so the next run reflects
  observed detector weighting rather than static calibration alone.
- **Rotation policy (G223).** `src/rotation.rs` adds `RotationPolicy`
  (`Never`, `PerSession`, `PerTarget`, `PerRequests(u64)`) and `RotationState`,
  giving callers a Tier-A config knob for *when* to rotate while `ProfileCycle`
  still decides *to what*. `RotationPolicy::should_rotate` and `record_request`
  handle per-session, per-target, and per-N-request boundaries with tests for
  the happy paths and the `PerRequests(0)`/`PerRequests(1)` edges.
- **Unified RNG/seed source + weighted persona selection (G225/G226/G231/G232).**
  The `guise-choice` subcrate now exports a deterministic `Seed` type plus
  `seed_from_u64` / `seeded_rng` / `seeded_rng_from_u64`. `guise::sampling` adds
  `RngSeed` with labelled `derive` so one persona seed can feed rotation,
  selection, behavior, and fingerprint layers without cross-correlation.
  `fingerprint::identity::seeded(seed)` builds a deterministic identity and
  `seeded_weighted(seed)` biases selection toward modal, common personas via the
  existing `rarity_score` weights while keeping every shipped profile reachable.
- **Rotation coherence tests (G221/G222/G224).** `src/rotation.rs` now tests
  that every rotated profile builds a coherent bundle, that rotation changes
  both the JS identity and the transport fingerprint, and that a bundle never
  mixes one persona's JS with another's TLS.
- **CreepJS/fpcollect/sannysoft source crawl + expanded coverage critic (G214).**
  `probe::completeness::KNOWN_FINGERPRINTER_CHECKS` grew by 20 checks mapped
  from public anti-bot check lists (chrome-object integrity, automation globals,
  navigator inheritance, UA-CH/timezone coherence, touch/DPR, error-stack
  presence, canvas/audio integrity, network info, notifications, Math IEEE-754,
  `document.hasFocus`, permissions, brave detection, WebRTC, window dimensions).
  Critical checks must match a catalogue probe; Medium/High checks are tracked
  gaps. CI still asserts zero Critical gaps for Firefox and Chrome.
- **Parallel probe evaluation over BiDi (G219).** `probe::run_for` now evaluates
  the catalogue concurrently via `futures::future::join_all` while preserving
  catalogue order, so oracle runtime scales with the slowest probe instead of the
  sum of latencies. `capture_page` already evaluated concurrently; both paths are
  now consistent.
- **`guise-oracle` reusable surface taxonomy crate (G220).** Extracted the core
  oracle contract types (`Severity`, `Probe`, `ProbeOutcome`, `Capture`,
  `DifferentialReport`, `ThreeWayReport`, etc.) into a new
  `libs/runtime/guise-oracle` crate with no browser-driver or TLS dependencies.
  `guise::probe` re-exports the types and keeps the runtime evaluation code.
  This gives downstream crates (`reynard`, `sear`, `captchaforge`) a cheap,
  versioned contract to share. Note: `DifferentialReport::to_scorecard(browser)`
  was replaced by the existing free function
  `guise::probe::scorecard_from_report(report, browser)` to keep the taxonomy
  crate independent of the scorecard module.
- **Unified request pacing + behavioral timing model (G227–G230).** Added
  `guise_pacing::RequestPacer` with `page_load`, `sub_resource`, and `api_call`
  profiles that sample from a bounded normal distribution. The pacer records
  HTTP status feedback (429/403 → doubled challenge multiplier, 2xx → decay)
  for rate-limit-aware pacing (G229), capped at `MAX_CHALLENGE_MULTIPLIER`.
  `human::timing::ActionDelay` now delegates every think-time distribution to
  the same `guise_pacing::BoundedNormalDelay` primitive, so behavioral timing
  and request pacing share one model rather than competing delay sources
  (G228). Tests assert every sampled delay stays within profile bounds and that
  the defaults produce many distinct values (no fixed sleeps (G230 / Law 7)).
- **Persona lifecycle pool (G233–G244).** New `persona_pool` module is the single
  owner of the full persona lifecycle: `acquire(target_domain)` selects a coherent
  identity (via `seeded_weighted`), assembles browser overrides + transport bundle,
  binds a `RequestPacer` / `SessionPacing`, and tracks the session until `release`.
  It enforces sticky per-domain identity reuse (G241/G242), refuses to rotate while
  a session has in-flight requests (G240), quarantines burned personas and their
  seeds so they are never reassigned (G243/G244), and deduplicates concurrent
  identities when the template pool allows (G235/G236). Derived overrides and bundles
  are cached on the `PersonaSession` (G237), and `snapshot` / `restore_snapshot`
  let a warmed persona survive process restarts (G238/G239). Covered by unit tests
  for lifecycle coherence, release, rotation blocking, stickiness, burn quarantine,
  distinct concurrent identities, snapshot round-trip, request-count preservation,
  and a capacity limit.
- **Tier-A configuration surface + hot reload (G245–G250).** New `config` module
  and `config` feature expose `GuiseConfig` with rotation, pacing, and pool knobs.
  The precedence chain is explicit: defaults → TOML file → CLI override. Methods
  like `from_toml_file`, `from_toml_str`, and `with_*` make the three layers
  composable, and a config-precedence test locks the ordering (G246). `GuiseConfig`
  converts directly into `persona_pool::PoolConfig` and can build the default
  `RequestPacer`. Under the `tier-b-toml` feature, `TierBPersonaDir` scans a
  directory of community persona TOMLs and reloads when a new file is dropped in
  (G247/G248). Module docs include a full TOML example and the lifecycle contract
  (G249); the public API is the stable entry point for consumers (G250).
- **Geo single-owner + Tier-B region presets (G127–G130).** Introduced
  `fingerprint::geo_region::GeoRegion` as the single source for every geography-
  derived persona surface: timezone, locale, languages, coordinates, and the
  proxy/WebRTC country. `NavigatorProfile` now stores an explicit `country` field
  and derives its geo fields from one `GeoRegion`, so the five surfaces cannot
  drift. Shipped built-in presets for US East/Central/West, EU Germany/UK/France,
  APAC Japan/India/Australia, and Canada, plus a `tier-b-toml`-gated loader for
  `tier_b/geo_regions/*.toml`. The loader validates every preset against the
  geo-coherence gate and rejects malformed or incoherent drop-ins loud (Law 10).
  Covered by tests proving every built-in and Tier-B preset is coherent and that
  all five surfaces come from one region owner.
- **Mouse trajectory realism + model ownership (G131–G134).** Hardened the
  Fitts's-law model in `human::mouse_driver` so `fitts_steps` derives ID from
  distance/target-size and produces a bounded, realistic step count. Added
  statistical tests that sampled mouse traces match the bundled human corpus on
  curvature and jerk, and tests proving the corpus contains micro-movements,
  overshoot+correction, and a variable pause distribution. The cross-project
  ownership regression fence (`tests/reynard_mouse_model_ownership.rs`) keeps
  guise as the single owner of the mouse model.
- **Unified typing model (G135–G138).** Collapsed the overlapping WPM-based
  `HumanTyper` and bigram-based `behavior::type_human` into one model.
  `human::typing::HumanTyper` now delegates all timing to
  `human::keystroke::plan_keystrokes` and only dispatches `keydown`/`keyup` events.
  `behavior::type_realistic` and `behavior::type_human` both route through the
  same executor; `TypingPlan::with_wpm` translates a WPM target into a speed
  multiplier on the canonical per-bigram envelopes. Added/updated tests for
  hot/cold/digit bigram gaps, hold-time buckets, typo+correction sequences,
  backspace-recovery envelope, and CV-floor realism across 64 seeds.
- **Scroll intent physics (G139–G140).** Refactored `human::scroll` so the flick
  physics is a pure, unit-tested `flick_steps` function. Added tests covering
  sum-to-target, friction-driven velocity decay, and intent ordering (searching
  fastest/least friction, idle slowest/longest pauses).
- **Single action-timing source (G141).** Moved the `idle_pause`, `micro_pause`,
  and `random_pause` distributions out of `human::behavior` and into
  `human::timing::ActionDelay` (`idle`, `between_actions`, `uniform`). The
  behavior wrappers now delegate, so all pacing delays flow through one module.
- **Adaptive and session-level pacing (G167–G169).** `SessionPacing` gained
  challenge-mode toggle (`enter_challenge_mode` / `exit_challenge_mode`) that
  doubles pauses when the persona is under suspicion, plus tests proving the
  multiplier and the long-session fatigue bounds. The existing fatigue factor
  (1.0 → ~1.5 over many actions) is now explicitly documented as the "tired
  persona" slow-down.
- **Behavioral telemetry schema (G170 / G179 / G180).** New `human::telemetry`
  module defines a normalized `BehavioralEvent` stream and a bounded
  `TelemetryCollector` for downstream scorers (e.g. captchaforge). Live drivers
  (`HumanMouse`, `HumanTyper`, `HumanScroller`) can attach a collector via
  `with_telemetry`. The `human` module docs now state the detector-class
  contract: timing/motion classifiers are defended here; fingerprint/network
  classifiers are defended elsewhere.
- **DOM-aware interaction geometry and semantics (G161–G166).** New
  `human::element_interaction` module queries the live bounding box of a CSS
  selector, rejects hidden/disabled/zero-size elements via
  `assert_interactable`, and samples human-distributed click offsets inside the
  element rather than at its exact center. Added `HumanMouse::move_to_element`,
  `hover_dwell_element`, `click_element`, and `hover_then_click_element`. New
  `human::behavior::keyboard` module provides trusted key-combo dispatch
  (`select_all`, `copy`, `paste`, `cut`, `key_combo`) with sampled stagger and
  hold times. Covered by pure unit tests plus an opt-in live regression test
  (`tests/element_interaction_live.rs`) that asserts visible targets are accepted
  and hidden/disabled/zero-size/missing targets are rejected.
- **Pointer, wheel, keyboard-event, IME fidelity + behavioral A/B fixture
  (G171–G178).** Added `human::pointer` for `PointerEvent` pressure/tilt/twist
  coherence per device class; `human::wheel` for `WheelEvent` `deltaMode` and
  granularity per device; `human::keyboard_event` for canonical
  `keydown → keypress → input → keyup` sequences and a single QWERTY `code`
  mapping now shared with `HumanTyper`; and `human::ime` for IME composition
  event ordering. `HumanScroller` now records the configured `WheelDevice`'s
  `deltaMode`. `human::detector_fixture` provides a timing-CV A/B fixture that
  scores a human-generated stream against a uniform bot stream, proving the
  human layer clears the same `HUMAN_TIMING_CV_FLOOR` detector bar used by the
  probe layer while a uniform cadence fails it. `BehavioralEvent` gained a
  `timestamp()` accessor for generic detector scoring.
- **Lie-detector probe set (G193/G194/G198).** New `probe::lie_detector`
  module adds a CreepJS-class probe that detects descriptor / toString
  inconsistencies (`navigator.webdriver`, `navigator.plugins`,
  `navigator.mimeTypes`, `window.chrome`) which are the exact tells left by
  naive JS spoofing. The classifier targets zero lies (empty array ⇒ `Pass`,
  1–2 ⇒ `Drift`, 3+ ⇒ `Critical`). Added unit tests for the classifier
  boundaries and an opt-in live regression test (`tests/lie_detector_live.rs`)
  that asserts a real Firefox produces zero lies.
- **Media/codec capability matrix expansion (G188).** The `probe::codec`
  coherence probe now includes async `MediaCapabilities.decodingInfo` checks
  for AAC and Opus alongside the existing `canPlayType`, `MediaSource`, and
  EME surface checks. The classifier flags a missing or denying
  MediaCapabilities stack as a `Drift` on the consumer-browser baseline.
- **Worker / ServiceWorker / Worklet realm probes (G200/G201).** New
  `probe::realm` module adds cross-realm coherence probes: a Web Worker
  navigator snapshot compared to the window snapshot, a ServiceWorker
  navigator snapshot probe, and an AudioWorklet/PaintWorklet presence probe.
  The classifier flags cross-realm `userAgent`, `platform`, `language`,
  `hardwareConcurrency`, `productSub`, or `webdriver` mismatches as `Drift`
  or `Critical`, catching spoofing that only patches `window`.
- **Oracle determinism + live-probe skip-loud audit (G189/G191/G218).**
  `probe::oracle::render_differential` now sorts divergences defensively
  before rendering, making the output byte-identical for the same divergence
  set regardless of input order. Audited all browser-spawning live tests to
  confirm each one skips loudly with the required env var and reason when the
  opt-in condition is not met.
- **Red-team probe expansion (G185/G186).** Added two CreepJS-class native-
  code red-team probes: `HTMLIFrameElement.contentWindow` getter and
  `Permissions.prototype.query`. Both catch the wrapper-toString tells left
  by anti-bot evasions that patch these high-value getters.
- **Local TLS+H2+TCP echo service (`guise-echo`, G067).** New crate
  `libs/runtime/guise-echo` terminates TLS 1.3 locally and returns a JSON snapshot
  of the connection's wire fingerprint. It parses the raw ClientHello with
  `tls-parser`, computes JA3/JA4 via `guise::fingerprint::ja3`, captures the HTTP/2
  connection preface plus SETTINGS/WINDOW_UPDATE/PRIORITY frames, and reads the
  host TCP/IP stack knobs (default TTL, timestamps/SACK/window-scaling flags). The
  service removes third-party flakiness from Layer-2 regression tests and gives the
  stealth stack an offline mirror for its own bytes. Ships a self-signed cert/key
  for local testing, a `BufferedStream` that replays the consumed ClientHello bytes
  into `tokio-rustls`, and an explicit ring crypto provider install to keep rustls
  0.23 deterministic when both `ring` and `aws-lc-rs` are in the dependency graph.
  Verified by a unit test for the buffered stream and four integration tests: TLS
  ClientHello + ALPN, H2 SETTINGS + WINDOW_UPDATE, H2 PRIORITY, and missing-preface
  handling; plus a TCP module unit test that asserts host knobs are reported on
  Linux and honestly absent elsewhere.
- **Offline Layer-2 regression gate (G068).** `guise/tests/local_echo_regression.rs`
  is wired into the `guise` crate as a declared test target (dev-dependency on
  `guise-echo`). It starts the echo service on an ephemeral port, performs a real
  TLS 1.3 handshake with a raw `rustls` client, and asserts the returned JSON
  carries a valid TLS 1.3 JA4, the advertised ALPN, honest H2 state, and host TCP
  diagnostics. It also recomputes JA4 from the echoed fields and asserts it equals
  the service's value, a deterministic, no-egress regression lock on the Layer-2
  computation path, replacing live-reflector flakiness for CI. Gated on
  `fingerprint` + `http`; full guise `--features browser,http --tests` stays green.
- **Cross-project mouse-model ownership (G131/R108/R266).** Verified that reynard's
  native `MouseTrajectories.hpp` / `camouGetMouseTrajectory` dead code has no
  callers (the BiDi path uses `guise::human::mouse` via `input.performActions`),
  removed the dead code from reynard patches and build files, and added
  `guise/tests/reynard_mouse_model_ownership.rs` as a regression fence ensuring
  guise remains the single owner of the mouse model.
- **Session-aged persona seeding (G126 / R148).** New `browser::session_age`
  module generates deterministic, per-identity `SessionAgeSeed` values and injects
  them into a live page via `apply_session_age`. `history.length` is raised to a
  plausible 2–12 via real `history.pushState` entries (not a getter override, so
  subsequent navigations update naturally), and `localStorage` receives a small
  set of ordinary site-state entries. Both `launch_profiled_firefox` and
  `launch_reynard_with_config` now apply the seed automatically, using the same
  stable identity key that drives canvas/audio/font noise. Locked by unit tests
  for deterministic generation, JS emission, and range bounds, plus an opt-in
  live test (`STEALTH_LIVE_BROWSER=1`) that asserts the seeded history and
  localStorage values survive navigation.
- **WebCodecs / MediaCapabilities surface probes (G120 / G121).** Added four
  modern media-capability surfaces to the fingerprint inventory
  (`VideoDecoder.isConfigSupported`, `VideoEncoder.isConfigSupported`, `VideoFrame`,
  `MediaCapabilities.decodingInfo`) and added a runtime presence probe for each in
  the core catalogue. Each probe is bridged to the shared surface taxonomy via
  `probe::surface_coverage`, so coverage remains build-enforced.
- **Persona seed trace test (G122 / G123).** Added
  `tests/unit/profile_bundle.rs::persona_seed_flows_unmodified_through_bundle_headers_and_tls`,
  which builds a `ProfileBundle` for every rotation profile and asserts that the
  same User-Agent, Accept, Accept-Language, and Accept-Encoding values reach the
  HTTP header layer unmodified and that the TLS family stays coherent with the
  browser identity.
- **Persona lock and mid-session drift test (G124 / G125).** Documented the
  immutability guarantee on `ProfileBundle` and added an opt-in live test
  `tests/session_drift.rs::persona_surfaces_are_identical_at_t0_and_after_activity`.
  It snapshots identity surfaces before and after navigation + canvas/audio
  activity, asserting no mid-session drift.
- **Live profile_js evaluation regression (G074).** Added
  `tests/profile_js_live_eval.rs::profile_js_evaluates_without_error_for_every_profile`,
  which evaluates the emitted `profile_js` for every shipped profile on a live
  Firefox page, closing the gap between the static bracket-balance guard and
  actual browser acceptance.
- **Runtime tamper-evasion proof for fingerprint noise (G085).** Extended the
  opt-in `stealth_core_tells` live test to apply `apply_fingerprint` and assert
  that the sealed methods for canvas, audio, fonts, and WebGL all report
  `[native code]` via `Function.prototype.toString`.
- **Engine-vs-JS spoof separation audit (G076-G079 / R146).** Documented the
  native engine surfaces handled by `reynard_config` and why the reynard path does
  not call the JS stealth / fingerprint layers. Documented why `launch_profiled_firefox`
  still requires the JS runtime layer (stock Firefox has no native spoofing for
  canvas, audio, fonts, or WebGL). Added source-audit tests in
  `src/browser/mod.rs` that prove `launch_reynard_with_config` never calls
  `apply_stealth_profile*` / `apply_fingerprint`, while `launch_profiled_firefox`
  calls both.
- **Live browser-catalog diff / real-browser truth values (G080 / G081).** Added
  `tests/browser_catalog_live.rs`, an opt-in live regression that captures the
  headers from a real stock Firefox and diffs them against the `firefox-linux`
  catalogue profile. Invariant Fetch-Metadata fields must match exactly; the full
  diff is written to `bench-results/browser_catalog_live_diff.json`. Updated the
  Firefox navigation Accept (`FIREFOX_NAVIGATION_ACCEPT`) and Accept-Language
  (`FIREFOX_ACCEPT_LANGUAGE`) constants to match stock Firefox 151.0.3: the
  navigation Accept no longer advertises `image/avif,image/webp` (those stay on
  image-element fetches), and the secondary language tag now uses q=0.9.
- **Single-source identity type (G082).** `NavigatorProfile` now carries the
  canonical `stealth_profile_name` and `hardware_index` so it can derive every
  other layer: `to_overrides()` produces the JS/pref overrides and `to_bundle()`
  (when the `http` feature is active) produces the browser+TLS bundle. Added
  regression tests proving the derived overrides match the canonical
  `profile_to_overrides_at` path and that the derived bundle passes the full
  coherence validator.
- **Evasion-layer engine-redundancy audit (G084 / G085).** Documented in
  `fingerprint/evasion.rs` that the JS noise layer is a stock-Firefox gap filler
  and must not re-implement persona identity or engine-native surfaces. Added
  `evasion_js_does_not_reimplement_engine_or_identity_surfaces` to lock that
  boundary, complementing the existing runtime tamper-evidence tests for sealed
  canvas/audio/font/WebGL methods.
- **Bundle internal coherence on build (G086 / G087).** `ProfileBundle::for_browser`
  now validates browser-side coherence at construction time and panics on an
  incoherent built-in profile. A new fallible `ProfileBundle::try_for_browser`
  returns `ProfileError` instead of panicking. Existing bundle tests already
  enforce the UA/Client-Hint major-version alignment; construction-time validation
  closes the window where an incoherent bundle could be used before explicit
  validation.
- **Seeded persona generator (G088 / G089).** Added
  `ProfileBundle::from_seed(seed: u64)`, a deterministic generator that selects
  from the rotation pool and therefore always produces a fully coherent bundle.
  Covered by determinism, rotation-pool coverage, and a `proptest` property
  asserting every generated seed passes the full coherence validator.
- **TLS/bundle browser-family alignment (G090 / G093).** Added
  `default_tls_profile_family_matches_bundle_browser_family` in
  `tls_profiles/tests.rs`, asserting that every rotation-profile bundle's default
  TLS ClientHello family matches the bundle's browser family (Chrome/Firefox/Safari).
  `ProfileBundle::try_for_browser` now asserts full browser+TLS coherence when the
  `http` feature is active, so personas with no compatible TLS profile (e.g.
  IE11) are refused at build time instead of silently paired with a mismatched
  ClientHello.
- **Firefox persona OS expansion (G091) + Firefox-engine launch gate (G092).**
  Added `StealthProfile::FirefoxMacStable` to complete the Firefox desktop OS
  matrix (Linux, Windows, macOS). The new persona is wired through the canonical
  projections: UA/platform/screen (`profile_facts`), WebGL hardware
  (`profile_hardware`), OS network stack/TCP fingerprint, TLS/H2/HTTP header-order
  family, and the `browser_catalog` (`firefox-macos`). The macOS Firefox persona
  passes the full bundle coherence validator and is covered by the rotation pool.
  `launch_profiled_firefox` now rejects any non-Firefox-family profile before
  spawning the engine; new `browser::browser_launch_profile_gate` tests prove
  Chrome/Safari are refused and FirefoxLinux/FirefoxMacStable are accepted.
- **Tier-B WebGL GPU persona library (G095).** Extracted the WebGL
  `UNMASKED_VENDOR_WEBGL` / `UNMASKED_RENDERER_WEBGL` pairs from the built-in
  profiles into drop-in TOML files under `tier_b/webgl/`. Added a
  `tier-b-toml`-gated `fingerprint::webgl_gpu_tier_b` loader with vendor-family
  classification, non-empty validation, oversize-file rejection, and the same
  Apple-platform-only GPU rule the bundle coherence gate enforces. Eight unit
  tests prove the shipped library covers all vendor families, contains every
  built-in profile GPU pair, and rejects malformed entries loud.
- **Tier-B font persona library (G096).** Extracted the Linux standard font
  whitelist from `browser::reynard` into `tier_b/fonts/linux_standard.toml` and
  made `fingerprint::font_tier_b::LINUX_STANDARD_FONTS` the single source used by
  `reynard_config`. Added a `tier-b-toml`-gated loader plus a regression test
  that keeps the const and the Tier-B file in sync.
- **Tier-B screen/DPR persona library (G097).** Extracted the screen dimensions
  and DPR values from the built-in profiles into drop-in TOML files under
  `tier_b/screen/` (desktop, macbook, mobile, tablet). Added a
  `tier-b-toml`-gated `fingerprint::screen_tier_b` loader with validation for
  positive width/height, positive finite DPR, and realistic color depths. Eight
  unit tests prove the shipped library covers all platform families, contains
  every built-in profile screen size, and rejects malformed entries loud.
- **Tier-B audio device persona library (G098).** Added platform-typical
  `navigator.mediaDevices.enumerateDevices()` audio input/output labels under
  `tier_b/audio_devices/` (linux, windows, macos). Added a `tier-b-toml`-gated
  `fingerprint::audio_device_tier_b` loader with kind validation and six unit
  tests covering library coverage, Linux defaults, malformed kind/label
  rejection, oversize rejection, and input/output helpers.
- **Tier-B voice list persona library (G099).** Added platform-typical
  `speechSynthesis.getVoices()` voice lists under `tier_b/voices/` (linux,
  windows, macos), each providing at least 16 voices to satisfy the real-browser
  probe expectation. Added a `tier-b-toml`-gated `fingerprint::voice_tier_b`
  loader with name/lang validation and five unit tests covering library
  coverage, the >=16-voice per-platform bar, and malformed/oversize rejection.
- **Single Tier-B persona-data tree (G100).** Documented the shared-tree
  contract in `tier_b/README.md` and added a regression test that locks the
  directory layout. The tree is the one source for all persona data consumed by
  guise and reynard, preventing duplicate copies across the stack.
- **Tier-B loader schema validation + chrome131_windows coherence +
  TOML→bundle round-trip (G101/G102/G103).** Every Tier-B loader already
  validates its TOML against a serde schema and rejects malformed entries loud.
  The shipped `tier_b/profiles/chrome131_windows.toml` is proven coherent via
  the full bundle validator, and a new regression test loads it and asserts the
  derived JS overrides match the Windows Chrome persona.
- **Persona rarity scoring (G104).** Added `fingerprint::rarity` with a
  `rarity_score` ordinal rank (1-100) for every shipped persona, an `is_modal`
  threshold helper, and a `personas_by_rarity` iterator. Chrome on Windows is
  the modal 100; legacy/niche personas score low so future selection logic can
  prefer populated real-world buckets over unique ones.
- **JA4+ family coverage (G002)**, new `fingerprint::ja4_family` module owns the
  full FoxIO JA4+ surface: `compute_ja4s` (TLS `ServerHello`), `compute_ja4l`
  (one-way latency + TTL), and `compute_ja4x` (X.509 certificate structural
  fingerprint). Includes TCP/QUIC/DTLS prefix support, GREASE-skipped version
  derivation, ASN.1 OID-to-hex encoding, and light-distance estimation helpers.
  The existing client-side JA4 hash helper was deduplicated into a shared
  `fingerprint::ja4_hash` primitive used by both `ja3` and `ja4_family`.
  Regression-locked by 20 unit/property tests including published FoxIO vectors
  for Sliver/SoftEther JA4S and a self-signed cert JA4X reference.
- **Section F test/dedup/wiring closure (G253/G256/G257/G260/G263/G264/G266/G268/G269/G281/G283/G284/G295/G301/G302/G313/G314/G315/G316/G318/G255).**
  Added a 10,000-case proptest asserting any seed produces a coherent bundle, a
  10,000-persona scale-corpus test, malformed/incoherent Tier-B TOML rejection
  tests, fuzz-style parser-resilience tests for the TOML loader, TLS profile
  parser, and header builder, and an integration test that drives the full
  config → pool lifecycle. Added runnable doctest examples for `GuiseConfig`,
  `PersonaPool`, and `ProfileBundle::from_seed`. Added seed reproducibility and
  capacity-limit tests to the persona pool. Refreshed `README.md` to use the
  correct crate name, state the categorical advantage honestly, and document the
  threat model. Added `MIGRATION.md` for compatibility-by-contract. Added
  Criterion benchmarks for `profile_js`, header build, bundle assembly,
  keystroke planning, and request-pacer sampling. Fixed feature-graph bugs:
  `browser` now depends on `human`, `human` now depends on `pacing`, and the
  rotation transport test now correctly requires `browser`; verified every
  single-feature build + lib tests pass.

### Fixed

- **Image subresource Accept no longer mis-classifies Safari as Firefox.** After
  `FIREFOX_NAVIGATION_ACCEPT` was updated to stock Firefox 151.0.3 it became
  byte-identical to `SAFARI_NAVIGATION_ACCEPT`. The old `family_image_accept`
  keyed the image Accept on the navigation Accept, so Safari personas received
  the Firefox image Accept (`image/avif,image/webp,*/*`) instead of the
  documented generic `*/*`. Replaced it with `profile_image_accept(profile)`, a
  profile-family switch that emits the correct image Accept for every persona.
- **`FIREFOX_SIG_ALGS` was missing Firefox's two SHA-1 signature algorithms** 
  the catalogue listed 9 of the 11 algorithms real Firefox advertises, omitting
  `ecdsa_sha1` (0x0203) and `rsa_pkcs1_sha1` (0x0201). Signature algorithms feed
  the JA4 extension hash, so any JA4 computed from the Firefox TLS profile
  diverged from a real Firefox's (a fingerprint tell). Found while building the
  FF-150 JA4 unit vector: guise's `compute_ja4` reproduces the measured FF-150 JA4
  `t13d1717h2_5b57614c22b0_e6dcd7ae0a9e` byte-for-byte **only** with all 11 algs
  present: which both fixes the catalogue and validates the whole JA3+JA4
  computation pipeline against real wire data (G110/G111). Locked by
  `ja3_and_ja4_for_firefox_150_match_the_measured_wire_values`.
- **`compute_ja4` emitted the wrong JA4 extension count, a fingerprint tell.**
  The JA4 `_a` extension count was taken from the SNI/ALPN-excluded list, but the
  FoxIO JA4 spec excludes SNI (0x0000) and ALPN (0x0010) **only from the sorted
  `_c` hash**, not from the count. So guise computed e.g. `t13d1715h2` where a real
  Firefox-150 (and `tls.peet.ws`, and JA4 databases) emit `t13d1717h2`: a JA4 that
  no real browser produces, i.e. trivially distinguishable. Now the count is over
  all non-GREASE extensions (SNI+ALPN included); the hash still excludes them.
  Caught by un-pinning the count (no prior test asserted it) and diffing against the
  measured FF-150 shape; regression-locked by
  `ja4_extension_count_includes_sni_and_alpn` and
  `ja4_for_firefox_150_has_the_measured_seventeen_seventeen_prefix`.
- **The entire per-profile JS stealth layer was silently dead.** `profile_js`
  (pins UA / hardwareConcurrency / vendor / WebGL / client-hints / window dims /
  touch) contained a `*/` *inside a block comment* (`screen.* (…avail*/colorDepth…)`),
  closing the comment early so the whole emitted script raised a `SyntaxError` on
  every page, and `apply_stealth_profile` swallowed the eval error (`let _ =`),
  reporting success while pinning nothing. The per-profile contract tests passed
  only because real Firefox-Linux values coincided with the pinned ones. Comment
  rewritten; `apply_stealth_profile` now propagates the immediate-evaluate error
  so a malformed override surfaces loudly instead of becoming a no-op.
- **Closed the bogus built-in JA4 catalogue finding.** The pre-existing
  `tls_targets` entries (`chrome-130-*`, `chrome-131-win-pq`, `firefox-131-linux`,
  `safari-17-mac`) carried hand-copied JA4 strings whose cipher/extension counts
  disagreed with their own JA3 lists. Rather than fabricate hashes, those
  approximate targets were removed; the built-in catalogue now contains only the
  measured `firefox-150-linux`, `firefox-151-linux`, and `chrome-146-linux`
  targets. `tls_targets::tests::every_builtin_target_is_ja3_ja4_count_consistent`
  makes count-consistency a fail-closed property of every shipped target.
- **Anti-uniqueness JA4 guard (G048/G049) + full-network-fingerprint coherence
  (G051).** New
  `tls_profiles::tests::every_rotation_persona_ja4_collides_with_a_populated_real_browser_cluster`
  loops every rotation persona through its TLS profile and asserts the computed
  JA4 collides with a measured, populated real-browser cluster (built-in targets
  + measured Safari-18). The unmeasured `EDGE_120` placeholder was removed and
  `EdgeWindowsStable` now maps to the measured Chrome-146 ClientHello (Edge is
  Chromium-derived; the old placeholder produced a JA4 that did not collide with
  any populated cluster). Legacy/IE11 personas are excluded from the rotation by
  design. A negative twin asserts a fabricated JA4 is not accepted as populated.
  New `session_coherence::tests::network_fingerprint` module closes G051: a
  positive property over `ROTATION_PROFILES` asserts every persona's combined
  TLS JA4 + HTTP/2 Akamai + TCP/JA4T + header-order fingerprint is populated and
  self-coherent, and that a synthetic capture matching the model returns
  `WireSelfProbe::Coherent`; a negative twin feeds a Windows persona a Linux TTL,
  Chrome H2, and Linux JA4T and asserts all three layers are surfaced.
- `profile_js` no longer pins `navigator.deviceMemory` for Firefox personas
  (Firefox does not expose that Chromium-only API; defining it was a cross-engine
  tell that the SyntaxError had been masking). Gated to Chromium personas.
- **The rest of the apply path stopped swallowing too (G262).** The *generic*
  `FIREFOX_STEALTH_JS` immediate-evaluate in `apply_stealth_profile`, and the
  whole `apply_fingerprint` call in `launch_profiled_firefox`, were still
  `let _ = …await`: a malformed generic automation-scrub, or a failed
  canvas/audio/WebGL evasion, shipped a half-stealthed page while the caller saw
  `Ok`. Both now `…map_err(…)?`. **Behaviour change for consumers:**
  `launch_profiled_firefox` / `launch_default_profiled_firefox` now return `Err`
  on an apply failure they previously hid (fail-closed beats shipping a
  detectable page).
- **Probe read-backs no longer fabricate a clean result on a failed deserialize
  (G261).** `fingerprint::collect_signals`, `probe::oracle::capture`, and
  `probe::run_for` did `eval.into_value().unwrap_or(Value::Null)`: a result that
  failed to deserialize became an all-defaults signal struct / a `"null"` cell /
  a `null` fed to the classifier. The differential oracle would then score two
  failed reads as **fingerprint-identical**, and a "tell-absent → Pass"
  classifier scored a failed read as a clean PASS. All three now surface the
  deserialize error (error cell / `ProbeError` / `Err`).

### Added

- **`fingerprint::akamai_h2`: the Akamai HTTP/2 fingerprint, structured
  (G011–G013).** Parses the published
  `SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header-order` string into typed fields
  (named SETTINGS accessors, PRIORITY frames, `m`/`p`/`a`/`s` order),
  canonicalizes back byte-for-byte, and **localizes** a divergence to the exact
  frame field: "pseudo-header order m,p,a,s vs m,a,s,p" / "INITIAL_WINDOW_SIZE
  131072 vs 6291456": instead of two opaque strings to eyeball-diff. The same
  un-decorator the cipher-list diagnostic applied to the ClientHello, now on the
  H2 frame. Wired three ways: (1) `validate_target_fields` parses the Akamai
  field **for real** (was a `split('|').count() == 4` sniff), so a malformed H2 in
  a built-in or dropped Tier-B target fails CLOSED with the offending token
  (Law 10); (2) `cluster` near-misses can name the contradicting H2 field;
  (3) `WireLayerMismatch::akamai_field_divergences()` localizes an egress
  self-probe mismatch (a Firefox persona leaking Chrome's H2). A cross-model
  coherence guard proves the emit model (`session_coherence::H2Profile`, which
  renders the string) and this canonical parser agree on every persona, two
  views of one format, kept from drifting. Screwdriver-bounded: it parses and
  diffs the operator's own H2 shape against a reference; it never decides a remote
  peer is a browser. Order-preserving (Safari's `2;4;3` SETTINGS order survives),
  fail-closed on every malformed section. ~18 unit tests incl. a catalogue
  round-trip tripwire over every shipped target.
- **`fingerprint::cluster`: wire-fingerprint cluster membership (G048–G051), the
  anti-uniqueness self-check.** `classify_observed(&ObservedFingerprint)` reports
  whether the shape the operator's *own* stack emits collides with a bundled
  real-browser [`FingerprintTarget`], a unique fingerprint is itself a stable
  tracking identifier, so "blend into a populated cluster" is the actual defense,
  not "look like a browser." JA4 is the required primary axis (GREASE-stripped +
  sorted → stable across handshakes); Akamai-H2 corroborates (a probed H2 frame
  that contradicts the JA4 match *breaks* membership, the cross-layer tell 
  rather than being ignored). Every surface is tri-state ([`SurfaceMatch`]:
  `Matched`/`Mismatched`/`NotProbed`) so "not probed" is never silently read as a
  contradiction. Screwdriver-bounded: it classifies the operator's emitted shape,
  never inspects a remote target; a `Distinguishable` verdict is a catalogue-
  coverage fact, explicitly **not** a uniqueness proof. 15 unit tests + a doctest,
  incl. a self-consistency property over the whole catalogue.
- `tls_targets`: **`firefox-150-linux`**: the current shipping reynard persona,
  measured live (`tls.peet.ws/api/all`, 2026-06-12) after the camoufox.cfg cipher
  fix restored `ecdhe_ecdsa_aes_128_sha` (0xc009): the 17-cipher `t13d1717h2`
  shape, sharing the JA4 cipher-hash `5b57614c22b0` with `firefox-131-linux` (same
  cipher set) but a distinct extension-hash and H2 frame. The catalogue previously
  topped out at FF-131 while FF-150 was the live persona, a measured-vs-catalogue
  gap now closed.
- `tls_targets::ja4_counts_match_ja3`: a pure JA3↔JA4 internal-consistency check
  (the JA4 `_a` cipher/extension counts must equal the JA3 cipher/extension list
  lengths). Surfaced a **finding**: only the newly-measured `firefox-150-linux`
  is consistent; every pre-existing target (`firefox-131-linux`, `chrome-130-*`,
  `chrome-131-win-pq`, `safari-17-mac`) and the `chrome_tls` snapshots have JA4
  values that were hand-copied, not derived from their JA3 (e.g. `safari-17-mac`
  lists 26 ciphers but its JA4 says 17). Soundly fixing them needs a measured
  ClientHello per browser, not fabricated, so the inconsistency is pinned by the
  `known_unmeasured_targets_have_ja3_ja4_count_inconsistencies` tripwire, which
  fails loudly when a real capture corrects one.
- **Tier-B externalization of the fingerprint-target catalogue** (`tier-b-toml`
  feature). `tls_targets::load_targets_from_toml` lets operators drop a TOML file
  to extend the built-in real-browser catalogue the cluster check classifies
  against (denser cluster ⇒ better anti-uniqueness), closing the "hardcoded lists
  banned; fingerprint sigs are Tier-B data" rule for this catalogue. Fails CLOSED:
  a malformed/oversized (64 KiB cap)/duplicate-label entry errors the whole load,
  never silently skips (Law 10). One shared `validate_target_fields` checks both
  the built-in catalogue and loaded entries (no duplicated format checks).
  `builtin_with(extra)` concatenates built-in + loaded for `classify_against`
  (`FingerprintTarget` is now `Copy`; the cluster slice bound relaxed from
  `&'static` to `&[..]`). Ships `tier_b/fingerprints/example.toml` carrying the
  real measured FF-150 shape under a distinct label as a worked schema example.
- `profile_js_is_syntactically_balanced_for_all_profiles`: a no-browser,
  comment/string-aware bracket-balance guard over every `StealthProfile`'s
  emitted script, plus a unit test proving it catches the premature-comment-close
  class. Closes the testing gap that let the dead-layer bug ship.
- Two `concat!`-self-immune source-audit guards fencing the swallow classes above:
  `browser::apply_path_law10_audit` (no `let _ =`/`.ok()`/`unwrap_or` on a Page
  apply/evaluate/preload call across `browser` + `fingerprint`) and
  `probe::into_value_no_swallow_audit` (no `into_value` read paired with a
  result-swallow). Both assert a site-count floor so they can't drift inert.
- Two `reqwest_client` tests that were named for a UA assertion they never made
  (built a client, `let _ = client`) now assert the persona's actual User-Agent
  on `browser_header_map_without_compression` (right engine + OS, no cross-engine
  token leak).
- **CreepJS live validation + a hardened `creepjs_gate`.** reynard passes the
  canonical IP-independent lie-detector outright, grade **A** / band "high"
  (CreepJS's top trust band, computed downstream of the lie set), stable over
  three live santhserver runs. Hardening the harness around that pass: the gate
  asserted only `grade != "F"` (decoration, it would pass an A→D slide of new
  fingerprint lies) and now asserts the trusted band `∈ {A,B}`, pinned to the
  real grade; the poll loop now waits for the late-resolving grade with the
  correct rationale; `into_value().unwrap_or_default()` (a silent Law-10
  deserialize swallow inside the harness) now surfaces loudly and retries; and a
  discovery run pinned the parser to CreepJS's real DOM, current builds render
  no scrapeable `lies (N)` panel or bare-`%` score (the `grade-X` class is the
  whole verdict), and the old `/trust/i` text sweep only matched `TrustedTypes`
  API names.

### Changed

- **File modularity pass (Law 5), five >500-LOC files brought under the limit.**
  `http::session_coherence` (760 LOC) split by responsibility into a thin mod-root
  re-exporting five submodules: `profiles` (per-engine header-order + HTTP/2/Akamai
  wire DATA), `transport` (TCP/IP↔H2↔header↔TLS coherence predicates), `persona`
  (the unified JS-to-wire gate + host network-OS checks), `wire_probe` (the X049
  egress self-probe), and `pool` (`SessionPool`); the public
  `http::session_coherence::*` path is byte-for-byte unchanged. The other four
  (`fingerprint::bundle` 613→281, `fingerprint::ja3` 578→260, `probe::redteam`
  561→284, `browser::reynard` 567→387) had their large inline `#[cfg(test)] mod
  tests` relocated to a sibling `…/tests.rs` via `#[path]` (the established
  pattern), pure code-motion. All module unit tests pass unchanged (guise lib 558,
  browser+http+tier-b features).
- **A real TLS Layer-2 tell found, root-caused, and fixed; the gate that should have
  caught it un-decorated.** `reynard_tls_matches_stock_firefox` only asserted that
  tls.peet.ws returned *some* JA3/JA4, the reynard-vs-stock match it computed was
  printed, never asserted, so a divergent ClientHello passed. Enforcing the namesake
  claim surfaced that reynard's hello carried 16 cipher suites vs stock Firefox 150's
  17: missing `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` (0xc009), the one ECDHE-CBC suite
  Camoufox's `StaticPrefList.yaml` defaults to `false`. Fixed in the reynard source's
  runtime autoconfig (`settings/camoufox.cfg`: `security.ssl3.ecdhe_ecdsa_aes_128_sha`
  → true; no Firefox rebuild, the .cfg is read at launch), proven live: reynard's
  degreased cipher AND extension lists now equal stock FF-150 (17==17) across runs. The
  gate now asserts the **GREASE-stripped** (RFC 8701) ordered cipher list, extension
  list, and Akamai H2 fingerprint, exact JA3/JA4 *hash* equality was demoted to a
  recorded diagnostic because Firefox's per-handshake GREASE makes a real browser's own
  JA3 vary launch-to-launch (an exact-hash assert would flap). Adds `is_grease`/
  `degreased`/`cipher_diff` helpers and `extensions`/`ja3_str` capture so future wire
  drift self-localizes to the exact suite/extension.
- Fixed two stale tests that asserted removed behavior: `gap.rs` availHeight
  `- 40` and `integration.rs` Mesa renderer. Both now reflect the current
  coherent design, screen.* and matched-host WebGL are left NATIVE (consistent
  with the matchMedia / real-pixel layers) rather than pinned.

## 0.1.0 - 2026-05-25

### Added

- `fingerprint`: lifted captchaforge `stealth_profiles` (12 `StealthProfile` variants, `ProfileOverrides`, `profile_js`, coherence tests).
- `human::keystroke`: lifted captchaforge `keystroke_timing` (bigram gaps, hold envelopes, `TypingPlan`, `plan_keystrokes`).
- `ProfileBundle` constructors (`chrome_131_macos`, `chrome_131_windows`, `firefox_133`, `safari_17_5`, `edge_131`) with browser/TLS family coherence validation.
- `http`: re-export `scanclient::tls_impersonate::*`; optional `StealthClient` behind `tls-impersonate`.
- `browser` feature: CDP `apply_stealth_profile` for chromiumoxide.
- `tier-b-toml` feature + sample `tier_b/profiles/chrome131_windows.toml`.
