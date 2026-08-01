//! Behavioral oracle for the canvas/audio farble (`evasion_js_source`), run under
//! Node.js against DOM stubs.
//!
//! The structure tests in `fingerprint::evasion` prove the emitted JS *mentions*
//! the right prototypes; that is shape, not truth (Law 6). This oracle EXECUTES
//! the exact emitted IIFEs against stub `CanvasRenderingContext2D` / `AudioBuffer`
//! / `AnalyserNode` prototypes and asserts the defense's load-bearing properties:
//!
//!   1. **getImageData is farbled**: the PRIMARY canvas-fingerprint path returns
//!      pixels that differ from the true buffer (regression guard for the recall
//!      hole where only toDataURL/toBlob were patched).
//!   2. **Stable within a session**: two reads of the same region/buffer are
//!      byte-identical (per-read jitter is itself a tell; deterministic farbling
//!      must not produce it).
//!   3. **Coherent across paths/regions**: a pixel read via a sub-rect and via the
//!      full canvas agree; toDataURL is stable too.
//!   4. **Audio getChannelData is farbled AND idempotent**: the OfflineAudioContext
//!      path differs from truth, and re-reading the SAME cached channel array does
//!      not double-perturb (the WeakSet guard).
//!   5. **No own-property tell**: the audio wrappers live on the prototype, so a
//!      buffer/analyser instance has no own `getChannelData`/`getFloatFrequencyData`.
//!   6. **toString stays native**: every wrapper reports `[native code]` via the
//!      `__seal` prelude.
//!
//! Requires `node` on PATH. When absent the test prints a loud SKIP and returns
//! rather than silently passing (Law 10) (on a host with Node it always runs).
#![cfg(feature = "browser")]

use guise::fingerprint::{evasion_js_source, FingerprintConfig};
use std::process::Command;

/// The Node harness. Reads the emitted guise JS path from argv[2], installs stub
/// DOM prototypes, `eval`s the guise JS (prelude + IIFEs) so the wrappers patch
/// those prototypes, then runs the behavioral assertions. Exits non-zero with a
/// message on the first failed assertion.
const HARNESS: &str = r#"
'use strict';
const fs = require('fs');
const guiseJs = fs.readFileSync(process.argv[2], 'utf8');

function fail(msg) { console.error('ORACLE FAIL: ' + msg); process.exit(1); }
function assert(cond, msg) { if (!cond) fail(msg); }

// Deterministic "true" pixel for a fingerprint: a pure function of absolute
// coords + channel. The stub's NATIVE getImageData returns these; the test
// recomputes them to prove the farble actually deviates from truth.
function truePixel(x, y, ch) { return (x * 31 + y * 17 + ch * 7 + 11) & 255; }

// ── stub CanvasRenderingContext2D / HTMLCanvasElement ──────────────────────
class CanvasRenderingContext2D {
  constructor(canvas) { this.canvas = canvas; const w = canvas.width, h = canvas.height;
    this._buf = new Uint8ClampedArray(w * h * 4); this._w = w; this._h = h; }
  _fillTruth() { for (let y = 0; y < this._h; y++) for (let x = 0; x < this._w; x++) {
      const i = (y * this._w + x) * 4;
      this._buf[i] = truePixel(x, y, 0); this._buf[i+1] = truePixel(x, y, 1);
      this._buf[i+2] = truePixel(x, y, 2); this._buf[i+3] = 255; } }
}
// NATIVE getImageData: copy the requested sub-rect out of the backing buffer.
CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh) {
  const data = new Uint8ClampedArray(sw * sh * 4);
  for (let row = 0; row < sh; row++) for (let col = 0; col < sw; col++) {
    const src = ((sy + row) * this._w + (sx + col)) * 4;
    const dst = (row * sw + col) * 4;
    data[dst] = this._buf[src]; data[dst+1] = this._buf[src+1];
    data[dst+2] = this._buf[src+2]; data[dst+3] = this._buf[src+3];
  }
  return { data, width: sw, height: sh };
};
CanvasRenderingContext2D.prototype.putImageData = function(img, dx, dy) {
  for (let row = 0; row < img.height; row++) for (let col = 0; col < img.width; col++) {
    const s = (row * img.width + col) * 4;
    const d = ((dy + row) * this._w + (dx + col)) * 4;
    this._buf[d] = img.data[s]; this._buf[d+1] = img.data[s+1];
    this._buf[d+2] = img.data[s+2]; this._buf[d+3] = img.data[s+3];
  }
};
CanvasRenderingContext2D.prototype.drawImage = function(src) {
  const sctx = src._ctx; this._buf.set(sctx._buf); // same dims in this test
};
// measureText returns a TextMetrics whose numbers depend on text + font, so the
// test can verify the per-session scale changes them while keeping them stable.
class TextMetrics { constructor(w) { this.width = w; this.actualBoundingBoxRight = w * 0.5; this.fontBoundingBoxAscent = 12; } }
CanvasRenderingContext2D.prototype.measureText = function(text) {
  const base = text.length * 7 + (this.font ? this.font.length : 0);
  return new TextMetrics(base);
};

class HTMLCanvasElement {
  constructor(w, h) { this.width = w; this.height = h; this._ctx = null; }
  getContext(kind) { if (kind !== '2d') return null;
    if (!this._ctx) { this._ctx = new CanvasRenderingContext2D(this); } return this._ctx; }
}
// NATIVE toDataURL: serialize the current backing buffer (so a farbled clone
// serializes farbled bytes, and the test can compare against the truth string).
HTMLCanvasElement.prototype.toDataURL = function() {
  return 'data:,' + Array.from(this._ctx._buf).join(',');
};

const document = { createElement(tag) { if (tag === 'canvas') return new HTMLCanvasElement(0, 0); return {}; } };

// ── stub AudioBuffer / AnalyserNode ────────────────────────────────────────
function trueSample(i) { return Math.sin(i * 0.13) * 0.5; }
class AudioBuffer {
  constructor(len) { this._len = len; this._chans = {}; }
  // NATIVE getChannelData: return the SAME cached Float32Array per channel, like
  // a real browser (so the idempotency (WeakSet) guard is actually exercised).
  getChannelData(ch) {
    if (!this._chans[ch]) { const a = new Float32Array(this._len);
      for (let i = 0; i < this._len; i++) a[i] = trueSample(i); this._chans[ch] = a; }
    return this._chans[ch];
  }
}
class AnalyserNode {
  getFloatFrequencyData(arr) { for (let i = 0; i < arr.length; i++) arr[i] = trueSample(i) * 100; }
  getFloatTimeDomainData(arr) { for (let i = 0; i < arr.length; i++) arr[i] = trueSample(i); }
}

// ── stub OffscreenCanvas (separate prototype from the 2D context above) ─────
class OffscreenCanvasRenderingContext2D {
  constructor(w, h) { this._w = w; this._h = h; }
}
OffscreenCanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh) {
  const data = new Uint8ClampedArray(sw * sh * 4);
  for (let row = 0; row < sh; row++) for (let col = 0; col < sw; col++) {
    const i = (row * sw + col) * 4;
    data[i] = truePixel(sx + col, sy + row, 0); data[i+1] = truePixel(sx + col, sy + row, 1);
    data[i+2] = truePixel(sx + col, sy + row, 2); data[i+3] = 255;
  }
  return { data, width: sw, height: sh };
};
class OffscreenCanvas {
  constructor(w, h) { this.width = w; this.height = h; this._ctx = null; }
  getContext(kind) { if (kind !== '2d') return null;
    if (!this._ctx) this._ctx = new OffscreenCanvasRenderingContext2D(this.width, this.height); return this._ctx; }
}

// Expose stubs as the globals the guise IIFEs reference, then run guise JS.
globalThis.CanvasRenderingContext2D = CanvasRenderingContext2D;
globalThis.HTMLCanvasElement = HTMLCanvasElement;
globalThis.document = document;
globalThis.AudioBuffer = AudioBuffer;
globalThis.AnalyserNode = AnalyserNode;
globalThis.OffscreenCanvas = OffscreenCanvas;
globalThis.OffscreenCanvasRenderingContext2D = OffscreenCanvasRenderingContext2D;
globalThis.TextMetrics = TextMetrics;
// Capture the NATIVE toDataURL before guise patches the prototype, so the "truth"
// serialization below is the raw one (the patch is prototype-level and would
// otherwise farble the truth canvas too, hiding the deviation).
const nativeToDataURL = HTMLCanvasElement.prototype.toDataURL;
const nativeMeasureText = CanvasRenderingContext2D.prototype.measureText;
// eslint-disable-next-line no-eval
(0, eval)(guiseJs); // indirect eval: run prelude + IIFEs at global scope.

// ── assertions ─────────────────────────────────────────────────────────────
const W = 16, H = 12;
const canvas = new HTMLCanvasElement(W, H);
const ctx = canvas.getContext('2d');
ctx._fillTruth();

// (1) getImageData deviates from the true buffer (the recall hole, closed).
const got = ctx.getImageData(0, 0, W, H);
let deviated = 0;
for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
  const i = (y * W + x) * 4;
  for (let ch = 0; ch < 3; ch++) if (got.data[i + ch] !== truePixel(x, y, ch)) deviated++;
}
assert(deviated > 0, 'getImageData returned the TRUE pixels unchanged, farble not applied (recall hole)');

// (2) Stable within a session: two reads of the same rect are byte-identical.
const a = ctx.getImageData(2, 1, 6, 5).data;
const b = ctx.getImageData(2, 1, 6, 5).data;
for (let i = 0; i < a.length; i++) assert(a[i] === b[i], 'getImageData unstable across reads (per-read jitter = tell)');

// (3) Coherent across regions: the pixel at absolute (4,3) is identical whether
// read via the full canvas or via a sub-rect that contains it.
function px(data, w, col, row, ch) { return data[(row * w + col) * 4 + ch]; }
const full = ctx.getImageData(0, 0, W, H).data;
const sub = ctx.getImageData(4, 3, 3, 3).data; // covers absolute (4,3)..(6,5)
for (let ch = 0; ch < 3; ch++)
  assert(px(full, W, 4, 3, ch) === px(sub, 3, 0, 0, ch), 'farble incoherent across overlapping regions');

// (4) Alpha is untouched (no visible transparency artifact).
for (let i = 3; i < got.data.length; i += 4) assert(got.data[i] === 255, 'alpha channel was perturbed');

// (5) toDataURL is stable and farbled (differs from a raw-truth serialization).
const d1 = canvas.toDataURL();
const d2 = canvas.toDataURL();
assert(d1 === d2, 'toDataURL unstable across reads');
const truthCanvas = new HTMLCanvasElement(W, H);
truthCanvas.getContext('2d')._fillTruth();
const truthStr = nativeToDataURL.call(truthCanvas);
assert(d1 !== truthStr, 'toDataURL serialized the TRUE pixels, farble not applied');

// (5b) measureText: scaled by a per-session factor (defeats the exact-width font
// fingerprint), stable across reads, and the returned object is still a
// TextMetrics (instanceof preserved through the Proxy). Layout impact is tiny.
ctx.font = '16px sans-serif';
const rawW = nativeMeasureText.call(ctx, 'mwMW09').width;
const m1 = ctx.measureText('mwMW09');
const m2 = ctx.measureText('mwMW09');
assert(m1.width !== rawW, 'measureText width unchanged, font farble not applied');
assert(m1.width === m2.width, 'measureText unstable across reads (per-read tell)');
assert(Math.abs(m1.width - rawW) < rawW * 0.01, 'measureText perturbation too large (would break layout)');
assert(m1 instanceof TextMetrics, 'measureText result is no longer a TextMetrics (Proxy broke instanceof)');
// Uniform scaling preserves equality/ordering, so font-presence detection still works.
const wA = ctx.measureText('AAAA').width, wB = ctx.measureText('AAAA').width;
assert(wA === wB, 'measureText not deterministic for equal inputs');

// (6) Audio getChannelData: farbled, idempotent (re-read identical), no own prop.
const buf = new AudioBuffer(64);
const c1 = Array.from(buf.getChannelData(0));
const c2 = Array.from(buf.getChannelData(0)); // same cached array, must NOT double-farble
let audioDev = 0;
for (let i = 0; i < c1.length; i++) { if (c1[i] !== trueSample(i)) audioDev++; assert(c1[i] === c2[i], 'getChannelData double-farbled on re-read (WeakSet idempotency broken)'); }
assert(audioDev > 0, 'getChannelData returned true samples, audio farble not applied (recall hole)');
assert(!Object.prototype.hasOwnProperty.call(buf, 'getChannelData'), 'getChannelData is an own-property tell (must be prototype-level)');

// (7) AnalyserNode wrappers are prototype-level (no own-property tell).
const an = new AnalyserNode();
assert(!Object.prototype.hasOwnProperty.call(an, 'getFloatFrequencyData'), 'getFloatFrequencyData is an own-property tell');

// (7b) OffscreenCanvas getImageData: farbled AND stable (the main-thread
// OffscreenCanvas bypass of the HTMLCanvas/2D-context patches is closed).
const off = new OffscreenCanvas(8, 8).getContext('2d');
const og = off.getImageData(0, 0, 8, 8).data;
let offDev = 0;
for (let y = 0; y < 8; y++) for (let x = 0; x < 8; x++) {
  const i = (y * 8 + x) * 4;
  for (let ch = 0; ch < 3; ch++) if (og[i + ch] !== truePixel(x, y, ch)) offDev++;
}
assert(offDev > 0, 'OffscreenCanvas getImageData returned true pixels, farble bypassed via OffscreenCanvas');
const oa = off.getImageData(1, 1, 4, 4).data;
const ob = off.getImageData(1, 1, 4, 4).data;
for (let i = 0; i < oa.length; i++) assert(oa[i] === ob[i], 'OffscreenCanvas getImageData unstable across reads');

// (8) toString stays native for every wrapper.
function ts(fn) { return Function.prototype.toString.call(fn); }
for (const [fn, name] of [
  [CanvasRenderingContext2D.prototype.getImageData, 'getImageData'],
  [HTMLCanvasElement.prototype.toDataURL, 'toDataURL'],
  [AudioBuffer.prototype.getChannelData, 'getChannelData'],
  [AnalyserNode.prototype.getFloatFrequencyData, 'getFloatFrequencyData'],
]) {
  assert(ts(fn).includes('[native code]'), name + '.toString() leaks the wrapper source');
}

console.log('ORACLE OK');
"#;

#[test]
fn canvas_and_audio_farble_behaves_under_node() {
    if Command::new("node").arg("--version").output().is_err() {
        eprintln!(
            "SKIP evasion_farble_node_oracle: `node` not found on PATH. \
             Install Node.js to run the canvas/audio farble behavioral oracle."
        );
        return;
    }

    let cfg = FingerprintConfig {
        canvas_noise: 0.05,
        audio_noise: true,
        // measureText farble rides font_noise; enable it so the oracle exercises it.
        font_noise: true,
        webgl_override: false,
        performance_noise: false,
        hardware_concurrency: None,
        device_memory: None,
        seed: Some(0x0BAD_F00D),
    };
    let guise_js = evasion_js_source(&cfg);

    let dir = std::env::temp_dir().join(format!("guise_farble_oracle_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let guise_path = dir.join("guise.js");
    let harness_path = dir.join("harness.js");
    std::fs::write(&guise_path, &guise_js).expect("write guise.js");
    std::fs::write(&harness_path, HARNESS).expect("write harness.js");

    let out = Command::new("node")
        .arg(&harness_path)
        .arg(&guise_path)
        .output()
        .expect("run node harness");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        out.status.success() && stdout.contains("ORACLE OK"),
        "canvas/audio farble oracle failed:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
}

/// Regression for the ASI IIFE-concatenation bug: the full default-config evasion
/// source (canvas + audio + font + webgl IIFEs) must EVALUATE to completion, not
/// abort partway. Two adjacent IIFEs joined by a bare newline parse as
/// `})()(function…)`: a call of the first IIFE's `undefined` return, which throws
/// and silently disables every noise surface after the first. We eval with NO DOM
/// globals: each IIFE no-ops via its own try/catch, so the ONLY way to throw is the
/// cross-IIFE concatenation. A clean eval proves the surfaces are correctly
/// separated by `;`.
#[test]
fn full_evasion_source_evaluates_without_aborting() {
    if Command::new("node").arg("--version").output().is_err() {
        eprintln!("SKIP full_evasion_source_evaluates_without_aborting: `node` not on PATH.");
        return;
    }

    // Every surface enabled so all IIFEs are concatenated, the worst case for the
    // separator bug.
    let cfg = FingerprintConfig {
        canvas_noise: 0.02,
        audio_noise: true,
        font_noise: true,
        webgl_override: true,
        performance_noise: true,
        hardware_concurrency: Some(8),
        device_memory: Some(8),
        seed: Some(7),
    };
    let guise_js = evasion_js_source(&cfg);
    // Sanity: more than one IIFE present (else the bug can't manifest and the test
    // would pass vacuously).
    assert!(
        guise_js.matches("})()").count() >= 2,
        "expected multiple evasion IIFEs; got source:\n{guise_js}"
    );

    let dir = std::env::temp_dir().join(format!("guise_asi_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let guise_path = dir.join("full.js");
    std::fs::write(&guise_path, &guise_js).expect("write full.js");

    let script = format!(
        "try{{ (0,eval)(require('fs').readFileSync({:?},'utf8')); console.log('EVAL OK'); }}\
         catch(e){{ console.error('THREW: '+e.message); process.exit(1); }}",
        guise_path.to_string_lossy()
    );
    let out = Command::new("node")
        .arg("-e")
        .arg(&script)
        .output()
        .expect("run node");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        out.status.success() && stdout.contains("EVAL OK"),
        "full evasion source aborted on eval (ASI IIFE-concat regression?):\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
}
