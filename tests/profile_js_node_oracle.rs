//! Behavioral oracle for `profile_js` (the persona IDENTITY injection), run under
//! Node.js in a fresh `vm` realm per profile.
//!
//! `profile_js` wraps every surface block in `try { … } catch (_) {}`, so a block
//! that throws in a real engine is SILENTLY swallowed, the surface then ships
//! un-spoofed while the caller sees a normal script (a Law-10 silent fallback the
//! string-match unit tests cannot see, and the live-browser eval test only runs
//! opt-in). This oracle executes the emitted JS for EVERY shipped profile and
//! asserts the resulting navigator/window/Intl state, so any silently-dropped
//! block fails loudly here.
//!
//! Each profile is evaluated in its OWN `vm` context: `profile_js` patches global
//! prototypes (`Navigator.prototype`, `Intl.DateTimeFormat`, `Date.prototype`, …),
//! so sharing a realm would let one persona's overrides contaminate the next.
//!
//! Requires `node`; loud SKIP when absent (Law 10), so it always runs on a host
//! with Node.
#![cfg(feature = "fingerprint")]

use guise::fingerprint::{profile_js, profile_to_overrides, ALL_PROFILES};
use std::process::Command;

/// Node harness: reads `[{name, js, ua, platform, vendor, lang0, langsLen,
/// hasBrands, hwc, sw, sh, tz}]` from argv[2]; per entry builds a fresh vm
/// context with stub DOM globals, evals the persona JS, then asserts the
/// resulting identity state. Exits non-zero listing every mismatch.
const HARNESS: &str = r#"
'use strict';
const fs = require('fs');
const vm = require('vm');
const entries = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

// Stub DOM globals set up INSIDE each context (so Object.create/defineProperty
// use the context's own primordials). profile_js patches Navigator.prototype,
// window.*, Intl/Date/Number/String, and (cross-OS personas) WebGL*.
const INIT = `
  globalThis.Navigator = function Navigator(){};
  globalThis.navigator = Object.create(Navigator.prototype);
  globalThis.window = {};
  globalThis.WebGLRenderingContext = function WebGLRenderingContext(){};
  globalThis.WebGLRenderingContext.prototype.getParameter = function(p){ return 'HOST-VENDOR-' + p; };
  globalThis.WebGL2RenderingContext = function WebGL2RenderingContext(){};
  globalThis.WebGL2RenderingContext.prototype.getParameter = function(p){ return 'HOST-VENDOR2-' + p; };
`;

const ASSERT = `
  (() => {
    const E = JSON.parse(globalThis.__EXP_JSON);
    const fails = [];
    const eq = (a, b, m) => { if (a !== b) fails.push(E.name + ' ' + m + ': got ' + JSON.stringify(a) + ' want ' + JSON.stringify(b)); };

    eq(navigator.userAgent, E.ua, 'navigator.userAgent');
    eq(navigator.platform, E.platform, 'navigator.platform');
    eq(navigator.vendor, E.vendor, 'navigator.vendor');
    // The classic CH cross-check: navigator.language MUST equal languages[0].
    eq(navigator.language, E.lang0, 'navigator.language');
    eq(Array.isArray(navigator.languages) ? navigator.languages[0] : undefined, E.lang0, 'navigator.languages[0]');
    eq(Array.isArray(navigator.languages) ? navigator.languages.length : -1, E.langsLen, 'navigator.languages.length');
    eq(navigator.hardwareConcurrency, E.hwc, 'navigator.hardwareConcurrency');
    // Window geometry must NOT be overridden: a JS getter cannot move the real
    // layout viewport (documentElement.clientWidth), matchMedia('(width)'), or
    // screen.*, so any pinned persona size that the real window does not match is a
    // contradiction (verified live, dump_geometry_truth, pinning innerWidth=1920
    // while the real window was 1366 produced innerWidth>screen.width AND
    // innerWidth!=clientWidth). Assert no own getter accessor was installed.
    for (const prop of ['innerWidth','innerHeight','outerWidth','outerHeight','screenX','screenY']) {
      const d = Object.getOwnPropertyDescriptor(window, prop);
      if (d && typeof d.get === 'function') fails.push(E.name + ' window.' + prop + ' overridden (must pass through to native)');
    }
    // maxTouchPoints IS a real capability signal (not a dimension contradicted by
    // any layout surface) and must still be pinned to the persona value.
    {
      const d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'maxTouchPoints');
      if (!(d && typeof d.get === 'function')) fails.push(E.name + ' maxTouchPoints not pinned (block silently dropped?)');
      else if (typeof d.get() !== 'number') fails.push(E.name + ' maxTouchPoints not numeric: ' + d.get());
    }

    // userAgentData: present + non-empty for Chromium, ABSENT for Firefox. A
    // silently-swallowed userAgentData block on a Chromium persona would ship a
    // Chromium UA with no Client Hints (a loud tell (and surface here)).
    if (E.hasBrands) {
      const uad = navigator.userAgentData;
      if (!uad) fails.push(E.name + ' userAgentData MISSING on a Chromium persona (block silently failed?)');
      else {
        if (!Array.isArray(uad.brands) || uad.brands.length === 0) fails.push(E.name + ' userAgentData.brands empty');
        if (typeof uad.getHighEntropyValues !== 'function') fails.push(E.name + ' getHighEntropyValues not a function');
      }
      // userAgentData is CREATED on Navigator.prototype (absent on a real Firefox),
      // so its descriptor must explicitly match Chrome's WebIDL attribute:
      // enumerable AND configurable true. A default enumerable:false is a tell.
      const uadDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgentData');
      if (!uadDesc || uadDesc.enumerable !== true) fails.push(E.name + ' userAgentData descriptor not enumerable (tell): ' + JSON.stringify(uadDesc && { e: uadDesc.enumerable, c: uadDesc.configurable }));
      // deviceMemory is likewise Chromium-only and created; same requirement.
      const dmDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'deviceMemory');
      if (dmDesc && dmDesc.enumerable !== true) fails.push(E.name + ' deviceMemory descriptor not enumerable (tell)');
    } else if (navigator.userAgentData !== undefined) {
      fails.push(E.name + ' userAgentData PRESENT on a non-Chromium persona (cross-engine tell)');
    }

    // Timezone: intl_spoof must make the DEFAULT Intl.DateTimeFormat resolve the
    // persona zone (not the host) (proves the Intl block applied, not swallowed).
    try {
      const tz = new Intl.DateTimeFormat().resolvedOptions().timeZone;
      eq(tz, E.tz, 'Intl.DateTimeFormat timeZone');
    } catch (e) { fails.push(E.name + ' Intl threw: ' + e.message); }

    // toString camouflage: an overridden getter must report native code.
    try {
      const d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent');
      const s = d && d.get ? Function.prototype.toString.call(d.get) : '';
      if (!s.includes('[native code]')) fails.push(E.name + ' userAgent getter toString leaks: ' + s);
    } catch (e) { fails.push(E.name + ' toString probe threw: ' + e.message); }

    // WebGL contract, keyed on engine family.
    //
    // * Firefox personas: the JS must NOT wrap getParameter at all. WebGL for a
    //   Gecko engine is spoofed by the webgl.override-unmasked-* prefs
    //   (build_user_js), which also reach Web Workers (a window-realm getter
    //   leaked the real host GPU there; tests/worker_webgl_cross_os_live.rs).
    //   The native stub values must pass through untouched here.
    // * Non-Firefox personas with a persona GPU (non-empty webglRenderer): the
    //   JS getter wrap pins UNMASKED_VENDOR (0x9245) and UNMASKED_RENDERER
    //   (0x9246) to the persona strings, and pins the masked GL_RENDERER
    //   (0x1F01) to the SAME persona string. The masked pin is deliberate:
    //   Firefox 151 stopped returning a generic masked RENDERER and now exposes
    //   the real GPU, so passing 0x1F01 through would leak the HOST GPU on a
    //   cross-OS persona; masked == unmasked matches what a real FF 151 reports.
    //   Masked GL_VENDOR (0x1F00) still passes through (native "Mozilla").
    if (E.webglRenderer && E.uaFirefox) {
      try {
        const gl = new WebGLRenderingContext();
        const unmaskedV = gl.getParameter(0x9245), unmaskedR = gl.getParameter(0x9246);
        if (!String(unmaskedV).startsWith('HOST-VENDOR')) fails.push(E.name + ' Firefox persona wrapped getParameter in JS (engine prefs own WebGL): ' + unmaskedV);
        if (!String(unmaskedR).startsWith('HOST-VENDOR')) fails.push(E.name + ' Firefox persona wrapped getParameter in JS (engine prefs own WebGL): ' + unmaskedR);
      } catch (e) { fails.push(E.name + ' WebGL probe threw: ' + e.message); }
    } else if (E.webglRenderer) {
      try {
        const gl = new WebGLRenderingContext();
        const maskedV = gl.getParameter(0x1F00), maskedR = gl.getParameter(0x1F01);
        const unmaskedV = gl.getParameter(0x9245), unmaskedR = gl.getParameter(0x9246);
        if (unmaskedV !== E.webglVendor) fails.push(E.name + ' UNMASKED_VENDOR = ' + unmaskedV + ' want ' + E.webglVendor);
        if (unmaskedR !== E.webglRenderer) fails.push(E.name + ' UNMASKED_RENDERER = ' + unmaskedR + ' want ' + E.webglRenderer);
        if (maskedR !== E.webglRenderer) fails.push(E.name + ' masked GL_RENDERER = ' + maskedR + ' want the persona renderer (masked==unmasked, FF151 behaviour)');
        if (maskedV === E.webglVendor) fails.push(E.name + ' GL_VENDOR leaks the GPU string (must be the generic engine value, not ' + E.webglVendor + ')');
        if (!String(maskedV).startsWith('HOST-VENDOR')) fails.push(E.name + ' GL_VENDOR did not pass through to the native value: ' + maskedV);
      } catch (e) { fails.push(E.name + ' WebGL probe threw: ' + e.message); }
    }

    return fails;
  })()
`;

let allFails = [];
for (const entry of entries) {
  const ctx = vm.createContext({});
  try {
    vm.runInContext(INIT, ctx);
    vm.runInContext(entry.js, ctx);
    ctx.__EXP_JSON = JSON.stringify({
      name: entry.name, ua: entry.ua, platform: entry.platform, vendor: entry.vendor,
      lang0: entry.lang0, langsLen: entry.langsLen, hasBrands: entry.hasBrands,
      hwc: entry.hwc, sw: entry.sw, sh: entry.sh, tz: entry.tz,
      webglVendor: entry.webglVendor, webglRenderer: entry.webglRenderer,
      uaFirefox: entry.uaFirefox,
    });
    const fails = vm.runInContext(ASSERT, ctx);
    allFails = allFails.concat(fails);
  } catch (e) {
    allFails.push(entry.name + ' THREW during eval (whole persona JS aborted): ' + e.message);
  }
}

if (allFails.length) { console.error('PROFILE ORACLE FAIL:\n' + allFails.join('\n')); process.exit(1); }
console.log('PROFILE ORACLE OK (' + entries.length + ' profiles)');
"#;

#[test]
fn profile_js_applies_identity_coherently_under_node() {
    if Command::new("node").arg("--version").output().is_err() {
        eprintln!("SKIP profile_js_node_oracle: `node` not on PATH.");
        return;
    }

    let entries: Vec<serde_json::Value> = ALL_PROFILES
        .iter()
        .map(|profile| {
            let ov = profile_to_overrides(profile);
            serde_json::json!({
                "name": format!("{profile:?}"),
                "js": profile_js(&ov),
                "ua": ov.user_agent,
                "platform": ov.platform,
                "vendor": ov.navigator_vendor,
                "lang0": ov.languages.first().cloned().unwrap_or_default(),
                "langsLen": ov.languages.len(),
                "hasBrands": !ov.brands.is_empty(),
                "hwc": ov.hardware_concurrency,
                "sw": ov.screen_width,
                "sh": ov.screen_height,
                "tz": ov.timezone,
                "webglVendor": ov.webgl_vendor,
                "webglRenderer": ov.webgl_renderer,
                "uaFirefox": ov.user_agent.contains("Firefox/"),
            })
        })
        .collect();
    assert!(!entries.is_empty(), "ALL_PROFILES is empty");

    let dir = std::env::temp_dir().join(format!("guise_profile_oracle_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let entries_path = dir.join("entries.json");
    let harness_path = dir.join("harness.js");
    std::fs::write(
        &entries_path,
        serde_json::to_string(&entries).expect("serialize"),
    )
    .expect("write entries");
    std::fs::write(&harness_path, HARNESS).expect("write harness");

    let out = Command::new("node")
        .arg(&harness_path)
        .arg(&entries_path)
        .output()
        .expect("run node");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        out.status.success() && stdout.contains("PROFILE ORACLE OK"),
        "profile_js identity oracle failed:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
}
