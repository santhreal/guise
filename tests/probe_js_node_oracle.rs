//! Behavioral oracle for the runtime probe JS, run under Node.js.
//!
//! The probe catalogue's classifiers are unit-tested with hand-written JSON, but
//! the JS expressions themselves are only ever EXECUTED against a live browser
//! over BiDi, never offline. So a probe whose JS inspects the wrong thing
//! produces a wrong verdict that no CI test can see (the exact "assembled JS no
//! test executes" bug class). This oracle executes a probe's real JS under Node
//! against a controlled DOM stub and asserts it scores the way its documentation
//! promises.
//!
//! Covered here: `creepjs.trust_score`. Its penalty table documents
//! "unstable canvas (per-read rand) -15", the tell a naive farble trips when it
//! perturbs the canvas DIFFERENTLY on each read. The fingerprint a farble
//! perturbs lives in the RGB channels; alpha is left untouched (a solid fill
//! holds it constant). The check must therefore compare RGB. This oracle drives
//! the probe twice with IDENTICAL stubs except the canvas read behavior, one
//! session-stable, one per-read-RGB-randomizing (alpha held constant, exactly
//! like a real farble), and asserts the canvas penalty fires for the randomizer
//! and ONLY the randomizer, isolated as a 15-point score DIFFERENCE so every
//! other penalty cancels. An alpha-only comparison (the prior bug) yields a 0
//! difference and fails here.
//!
//! Requires `node`; loud SKIP when absent (Law 10).
#![cfg(feature = "browser")]

use std::process::Command;

/// Node harness: argv[2] is the probe JS. Runs it in two fresh vm contexts whose
/// only difference is whether the stubbed canvas returns per-read-varying RGB
/// (alpha always constant). Prints `{stable, varying}` as JSON.
const HARNESS: &str = r#"
'use strict';
const fs = require('fs');
const vm = require('vm');
const probeJs = fs.readFileSync(process.argv[2], 'utf8');

function runScore(vary) {
  const ctx = vm.createContext({});
  const INIT = `
    globalThis.__call = 0;
    globalThis.__VARY = ${vary};
    // Rich-enough navigator so the un-try/catch'd top-of-script reads
    // (webdriver/plugins/mimeTypes/languages) do not throw or penalize.
    globalThis.navigator = { webdriver: false, plugins: { length: 3 }, mimeTypes: { length: 2 }, languages: ['en-US','en'] };
    globalThis.window = globalThis;
    globalThis.__mkData = function() {
      const N = 50 * 50 * 4;
      const arr = new Array(N);
      // Base image: deterministic pattern; alpha (every 4th byte) pinned to 255.
      for (let i = 0; i < N; i++) { arr[i] = (i % 4 === 3) ? 255 : (i % 7); }
      // The naive-farble tell: on the SECOND+ read, perturb RGB only, never
      // alpha. A correct, session-stable farble (and a real browser) would
      // return byte-identical data here.
      if (globalThis.__VARY && globalThis.__call > 0) {
        for (let i = 0; i < N; i++) { if (i % 4 !== 3) arr[i] = (arr[i] + 1) % 256; }
      }
      globalThis.__call++;
      return arr;
    };
    globalThis.document = {
      createElement: function() {
        return {
          width: 0, height: 0,
          getContext: function(kind) {
            if (kind === '2d') {
              return { fillStyle: '', fillRect: function(){}, getImageData: function(){ return { data: globalThis.__mkData() }; } };
            }
            return null; // no WebGL surface in this oracle (its penalty is out of scope)
          }
        };
      }
    };
  `;
  vm.runInContext(INIT, ctx);
  return vm.runInContext(probeJs, ctx);
}

const out = { stable: runScore(false), varying: runScore(true) };
if (typeof out.stable !== 'number' || typeof out.varying !== 'number') {
  console.error('PROBE ORACLE FAIL: score not a number: ' + JSON.stringify(out));
  process.exit(1);
}
console.log(JSON.stringify(out));
"#;

#[test]
fn creepjs_trust_score_penalizes_per_read_rgb_canvas_under_node() {
    if Command::new("node").arg("--version").output().is_err() {
        eprintln!("SKIP probe_js_node_oracle: `node` not on PATH.");
        return;
    }

    // Pull the REAL probe JS straight from the shipped catalogue (not a copy).
    let probe_js = guise::probe::probes()
        .into_iter()
        .find(|p| p.name == "creepjs.trust_score")
        .expect("creepjs.trust_score probe must be in the catalogue")
        .js;

    let dir = std::env::temp_dir().join(format!("guise_probe_oracle_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let js_path = dir.join("probe.js");
    let harness_path = dir.join("harness.js");
    std::fs::write(&js_path, probe_js).expect("write probe js");
    std::fs::write(&harness_path, HARNESS).expect("write harness");

    let out = Command::new("node")
        .arg(&harness_path)
        .arg(&js_path)
        .output()
        .expect("run node");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        out.status.success(),
        "node harness errored:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("bad harness output {stdout:?}: {e}"));
    let stable = parsed["stable"].as_i64().expect("stable score");
    let varying = parsed["varying"].as_i64().expect("varying score");

    // The canvas penalty is documented as exactly -15 and is the ONLY thing that
    // differs between the two runs, so the per-read-RGB-randomizing canvas must
    // score precisely 15 below the session-stable one. An alpha-only comparison
    // (the bug) leaves alpha constant in both runs → diff 0 → this fails.
    assert_eq!(
        stable - varying,
        15,
        "creepjs trust score must drop by the documented 15 when the canvas \
         randomizes RGB per read; got stable={stable}, varying={varying} (diff \
         {}). A 0 diff means the canvas-instability check inspects a channel the \
         farble never touches (alpha), not RGB.",
        stable - varying
    );
}

/// Node harness for the worklet-presence probe: stubs `AudioContext` with the
/// `audioWorklet` accessor on its PROTOTYPE and a constructor-call counter, runs
/// the probe, and reports whether it detected `audioWorklet` and whether it
/// CONSTRUCTED an AudioContext to do so.
const HARNESS_WORKLET: &str = r#"
'use strict';
const fs = require('fs');
const vm = require('vm');
const probeJs = fs.readFileSync(process.argv[2], 'utf8');
const ctx = vm.createContext({});
const INIT = `
  globalThis.__ctorCalls = 0;
  globalThis.AudioWorklet = function AudioWorklet(){};
  globalThis.AudioContext = function AudioContext(){ globalThis.__ctorCalls++; };
  // audioWorklet is a getter on the prototype chain (BaseAudioContext.prototype
  // in real engines) (readable with the in-operator without instantiating).
  Object.defineProperty(globalThis.AudioContext.prototype, 'audioWorklet', { get: function(){ return {}; }, configurable: true });
  globalThis.window = globalThis;
`;
vm.runInContext(INIT, ctx);
const result = vm.runInContext(probeJs, ctx);
const ctorCalls = vm.runInContext('globalThis.__ctorCalls', ctx);
console.log(JSON.stringify({ audioWorklet: !!(result && result.audioWorklet), ctorCalls: ctorCalls }));
"#;

#[test]
fn worklet_presence_probe_detects_audioworklet_without_constructing_a_context() {
    if Command::new("node").arg("--version").output().is_err() {
        eprintln!("SKIP probe_js_node_oracle: `node` not on PATH.");
        return;
    }

    let probe_js = guise::probe::probes()
        .into_iter()
        .find(|p| p.name == "realm: AudioWorklet / PaintWorklet presence")
        .expect("worklet-presence probe must be in the catalogue")
        .js;

    let dir = std::env::temp_dir().join(format!("guise_worklet_oracle_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let js_path = dir.join("probe.js");
    let harness_path = dir.join("harness.js");
    std::fs::write(&js_path, probe_js).expect("write probe js");
    std::fs::write(&harness_path, HARNESS_WORKLET).expect("write harness");

    let out = Command::new("node")
        .arg(&harness_path)
        .arg(&js_path)
        .output()
        .expect("run node");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        out.status.success(),
        "node harness errored:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("bad harness output {stdout:?}: {e}"));

    // The probe must still detect AudioWorklet support from the prototype accessor.
    assert_eq!(
        parsed["audioWorklet"].as_bool(),
        Some(true),
        "worklet probe must report audioWorklet present when the accessor is on the prototype"
    );
    // …and it must do so WITHOUT instantiating an AudioContext. The prior code
    // evaluated `(new AudioContext()).audioWorklet`, which constructs (and leaks)
    // one (and throws the whole probe once the per-document context cap is hit).
    assert_eq!(
        parsed["ctorCalls"].as_i64(),
        Some(0),
        "worklet probe must not construct an AudioContext to read audioWorklet (leak / \
         throws at the per-document cap); it constructed {:?}",
        parsed["ctorCalls"]
    );
}
