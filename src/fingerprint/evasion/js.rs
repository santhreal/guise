//! JavaScript generators for fingerprint evasion surfaces.
//!
//! Each function returns a self-contained IIFE string that patches one
//! high-entropy browser surface. They are deterministic for a fixed seed and
//! are assembled by [`super::evasion_js_source`].

pub(crate) fn normalized_canvas_noise(noise: f64) -> f64 {
    if noise.is_finite() {
        noise.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

pub(crate) fn canvas_noise_js(seed: u32, noise: f64) -> String {
    format!(
        r#"(function() {{
    try {{
        const baseSeed = {seed};
        const noise = {noise};
        // Deterministic per-pixel farble: a pure function of (baseSeed, ABSOLUTE
        // x, y, channel). Keying on absolute canvas coordinates (not a running
        // counter) makes the perturbation:
        //   * STABLE within a session, two reads of the same region return the
        //     IDENTICAL bytes, so the canvas is not "unstable" (per-read jitter is
        //     itself a fingerprint tell that CreepJS flags);
        //   * COHERENT across extraction paths, a sub-rect getImageData and the
        //     full-canvas read behind toDataURL agree on every shared pixel;
        //   * UNLINKABLE across sessions, baseSeed varies per session, so the
        //     fingerprint differs run-to-run while staying internally consistent.
        function farbleChannel(value, x, y, ch) {{
            let h = (baseSeed ^ (((x + 1) * 2654435761) >>> 0) ^ (((y + 1) * 40503) >>> 0) ^ (((ch + 1) * 668265263) >>> 0)) >>> 0;
            h = (((h ^ (h >>> 15)) >>> 0) * 2246822519) >>> 0;
            h = (((h ^ (h >>> 13)) >>> 0) * 3266489917) >>> 0;
            h = (h ^ (h >>> 16)) >>> 0;
            const delta = ((h / 4294967296) * 2 - 1) * noise * 255;
            return Math.max(0, Math.min(255, value + delta));
        }}
        // Perturb an ImageData's RGB bytes in place, keyed on absolute coords.
        // Alpha is intentionally left untouched (perturbing it risks visible
        // transparency artifacts and standard canvas fingerprints read RGB). `ox`
        // / `oy` are the region's top-left in canvas space so the key is absolute.
        function farbleImageData(imageData, ox, oy) {{
            const data = imageData.data;
            const w = imageData.width;
            const h = imageData.height;
            for (let row = 0; row < h; row++) {{
                for (let col = 0; col < w; col++) {{
                    const i = (row * w + col) * 4;
                    const ax = ox + col;
                    const ay = oy + row;
                    data[i]     = farbleChannel(data[i],     ax, ay, 0);
                    data[i + 1] = farbleChannel(data[i + 1], ax, ay, 1);
                    data[i + 2] = farbleChannel(data[i + 2], ax, ay, 2);
                }}
            }}
            return imageData;
        }}

        // (1) CanvasRenderingContext2D.getImageData, the PRIMARY canvas-fingerprint
        // extraction path. Without this wrapper a fingerprinter reads true pixels
        // straight off the 2D context and the toDataURL/toBlob farble below is
        // bypassed entirely. `origGetImageData` is captured ONCE and reused by the
        // serialization clone below so a pixel is never farbled twice.
        let origGetImageData = null;
        if (typeof CanvasRenderingContext2D !== 'undefined'
            && CanvasRenderingContext2D.prototype.getImageData) {{
            origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            CanvasRenderingContext2D.prototype.getImageData = __seal(function(sx, sy, sw, sh, settings) {{
                const imageData = settings === undefined
                    ? origGetImageData.call(this, sx, sy, sw, sh)
                    : origGetImageData.call(this, sx, sy, sw, sh, settings);
                try {{ return farbleImageData(imageData, sx | 0, sy | 0); }}
                catch (_) {{ return imageData; }}
            }}, 'getImageData');
        }}

        // (1b) OffscreenCanvasRenderingContext2D.getImageData, the same pixel-read
        // path on an OffscreenCanvas (a separate prototype). A fingerprinter using
        // `new OffscreenCanvas(w,h).getContext('2d').getImageData(...)` on the main
        // thread would otherwise bypass the wrapper above entirely. (Worker-realm
        // OffscreenCanvas needs per-worker injection the engine layer owns; it is a
        // documented residual, not silently claimed here.)
        if (typeof OffscreenCanvasRenderingContext2D !== 'undefined'
            && OffscreenCanvasRenderingContext2D.prototype.getImageData) {{
            const origOffscreenGetImageData = OffscreenCanvasRenderingContext2D.prototype.getImageData;
            OffscreenCanvasRenderingContext2D.prototype.getImageData = __seal(function(sx, sy, sw, sh, settings) {{
                const imageData = settings === undefined
                    ? origOffscreenGetImageData.call(this, sx, sy, sw, sh)
                    : origOffscreenGetImageData.call(this, sx, sy, sw, sh, settings);
                try {{ return farbleImageData(imageData, sx | 0, sy | 0); }}
                catch (_) {{ return imageData; }}
            }}, 'getImageData');
        }}

        // (2) toDataURL / toBlob, the serialization path. The browser serializes
        // from the native pixel buffer (NOT through the JS getImageData above), so
        // this path needs its own farble. noisyClone reads the source's TRUE pixels
        // via `origGetImageData` (never the wrapped one, no double farble) and
        // applies the SAME coordinate-keyed perturbation, so both paths agree.
        function noisyClone(source) {{
            if (!source || source.width === 0 || source.height === 0 || !origGetImageData) return source;
            const clone = document.createElement('canvas');
            clone.width = source.width;
            clone.height = source.height;
            const ctx = clone.getContext('2d');
            if (!ctx) return source;
            ctx.drawImage(source, 0, 0);
            const imageData = origGetImageData.call(ctx, 0, 0, clone.width, clone.height);
            farbleImageData(imageData, 0, 0);
            ctx.putImageData(imageData, 0, 0);
            return clone;
        }}
        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = __seal(function(type, quality) {{
            try {{
                const clone = noisyClone(this);
                return origToDataURL.call(clone, type, quality);
            }} catch (_) {{
                return origToDataURL.call(this, type, quality);
            }}
        }}, 'toDataURL');
        if (HTMLCanvasElement.prototype.toBlob) {{
            const origToBlob = HTMLCanvasElement.prototype.toBlob;
            HTMLCanvasElement.prototype.toBlob = __seal(function(callback, type, quality) {{
                try {{
                    const clone = noisyClone(this);
                    return origToBlob.call(clone, callback, type, quality);
                }} catch (_) {{
                    return origToBlob.call(this, callback, type, quality);
                }}
            }}, 'toBlob');
        }}
    }} catch (_) {{}}
}})()"#
    )
}

pub(crate) fn audio_noise_js(seed: u32) -> String {
    format!(
        r#"(function() {{
    try {{
        const baseSeed = {seed};
        // (1) AudioBuffer.getChannelData (the CANONICAL audio fingerprint path).
        // FingerprintJS / CreepJS render an oscillator through an
        // OfflineAudioContext and read the rendered samples here; the realtime
        // AnalyserNode path below is secondary. Patched at PROTOTYPE level so every
        // buffer (offlineCtx.startRendering(), ctx.createBuffer(), new AudioBuffer)
        // is covered, with no per-instance own-property added as a tell.
        //
        // The buffer is STATIC, so the farble must be IDEMPOTENT: a WeakSet records
        // already-perturbed channel arrays, so repeated reads of the same buffer
        // return IDENTICAL samples (per-read drift would itself be a tell) while the
        // per-session baseSeed keeps the fingerprint unlinkable across sessions.
        const __audioFarbled = new WeakSet();
        function farbleStaticSamples(arr) {{
            if (!arr || __audioFarbled.has(arr)) return;
            let state = baseSeed >>> 0;
            for (let i = 0; i < arr.length; i++) {{
                state = (((state >>> 0) * 1664525 + 1013904223) >>> 0);
                arr[i] += ((state / 4294967296) * 2 - 1) * 0.0001;
            }}
            try {{ __audioFarbled.add(arr); }} catch (_) {{}}
        }}
        if (typeof AudioBuffer !== 'undefined' && AudioBuffer.prototype.getChannelData) {{
            const origGetChannelData = AudioBuffer.prototype.getChannelData;
            AudioBuffer.prototype.getChannelData = __seal(function(channel) {{
                const data = origGetChannelData.call(this, channel);
                try {{ farbleStaticSamples(data); }} catch (_) {{}}
                return data;
            }}, 'getChannelData');
        }}
        // (2) AnalyserNode realtime readers. These fill a caller-supplied array with
        // the CURRENT spectrum, which legitimately varies over time, so per-call
        // additive noise is correct here (no idempotency needed, the underlying
        // data is not static). Patched on the prototype so analysers from BOTH
        // ctx.createAnalyser() and `new AnalyserNode(ctx)` are covered.
        // (Byte-quantised variants getByte*Data derive 0..255 buckets where a
        // sub-LSB float delta is lost; they are a documented residual covered in
        // aggregate by the live oracle, not silently claimed here.)
        if (typeof AnalyserNode !== 'undefined' && AnalyserNode.prototype) {{
            const proto = AnalyserNode.prototype;
            const wrapRealtime = function(name) {{
                if (!proto[name]) return;
                const orig = proto[name];
                proto[name] = __seal(function(array) {{
                    orig.call(this, array);
                    let state = (baseSeed ^ 2654435769) >>> 0;
                    for (let i = 0; i < array.length; i++) {{
                        state = (((state >>> 0) * 1664525 + 1013904223) >>> 0);
                        array[i] += ((state / 4294967296) * 2 - 1) * 0.001;
                    }}
                }}, name);
            }};
            wrapRealtime('getFloatFrequencyData');
            wrapRealtime('getFloatTimeDomainData');
        }}
    }} catch (_) {{}}
}})()"#
    )
}

pub(crate) fn font_noise_js(seed: u32) -> String {
    format!(
        r#"(function() {{
    try {{
        const baseSeed = {seed};
        // measureText is the dominant FONT fingerprint: a script renders each
        // candidate font and compares text width against a fallback to enumerate
        // installed fonts. Scale every TextMetrics number by a per-session factor
        // very close to 1, applied UNIFORMLY. Uniform scaling PRESERVES equality
        // and ordering between fonts (k*a == k*b iff a == b), so font-presence
        // detection and text layout are unaffected, while the exact sub-pixel width
        // VECTOR, the actual cross-session fingerprint, is perturbed. O(1) per
        // call, so unlike a per-pixel readback it is not a timing tell, and it is
        // stable within a session (factor fixed by baseSeed).
        //
        // The previous defense here perturbed `FontFaceSet.forEach` enumeration,
        // which (a) only iterates page-LOADED @font-face faces, not the installed
        // system fonts a fingerprinter actually probes, and (b) made the iterated
        // count disagree with `document.fonts.size`: a guise-INTRODUCED coherence
        // tell. It was removed in favour of the measureText defense above.
        const mtScale = 1 + (((((baseSeed >>> 8) & 0xffff) / 65535) - 0.5) * 0.0006);
        function patchMeasureText(proto) {{
            if (!proto || !proto.measureText) return;
            const origMeasureText = proto.measureText;
            proto.measureText = __seal(function(text) {{
                const m = origMeasureText.call(this, text);
                try {{
                    return new Proxy(m, {{ get(t, prop) {{
                        const v = Reflect.get(t, prop, t);
                        return (typeof v === 'number') ? v * mtScale : v;
                    }} }});
                }} catch (_) {{ return m; }}
            }}, 'measureText');
        }}
        patchMeasureText(typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype : null);
        patchMeasureText(typeof OffscreenCanvasRenderingContext2D !== 'undefined' ? OffscreenCanvasRenderingContext2D.prototype : null);
    }} catch (_) {{}}
}})()"#
    )
}

pub(crate) fn performance_noise_js(seed: u32) -> String {
    format!(
        r#"(function() {{
    try {{
        let state = {seed};
        const nextNoise = function() {{
            state = (((state >>> 0) * 1664525 + 1013904223) >>> 0);
            return (state / 4294967296) * 0.05;
        }};
        const target = typeof Performance !== 'undefined' && Performance.prototype
            ? Performance.prototype
            : performance;
        const origNow = target.now;
        target.now = __seal(function() {{
            const real = origNow.call(this);
            return Math.round(real * 10) / 10 + nextNoise();
        }}, 'now');
    }} catch (_) {{}}
}})()"#
    )
}

pub(crate) fn hardware_concurrency_js(cores: u8) -> String {
    format!(
        r#"(function() {{
    try {{
        Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {{
            get: __seal(() => {cores}, 'get hardwareConcurrency'),
            configurable: true,
        }});
    }} catch (_) {{}}
}})()"#
    )
}

pub(crate) fn device_memory_js(mem: u8) -> String {
    format!(
        r#"(function() {{
    try {{
        Object.defineProperty(Navigator.prototype, 'deviceMemory', {{
            get: __seal(() => {mem}, 'get deviceMemory'),
            configurable: true,
        }});
    }} catch (_) {{}}
}})()"#
    )
}

/// WebGL shape patch. Ensures `WEBGL_debug_renderer_info` is in the extension list
/// (the renderer/vendor string spoof reads its `UNMASKED_*` constants).
///
/// `getShaderPrecisionFormat` is deliberately LEFT NATIVE (pass-through) and NOT
/// patched here. An earlier version normalized the returned `WebGLShaderPrecisionFormat`
/// via `Object.defineProperty(result, 'precision'/'rangeMin'/'rangeMax', …)`, but those
/// are PROTOTYPE getters on a real Firefox, defining them on the instance creates OWN
/// data properties the real object never has, so `result.hasOwnProperty('precision')`
/// flips true (a CreepJS-class descriptor lie). The normalization bought nothing on
/// desktop either: highp float is universally `{23,127,127}` on every desktop OS, and
/// the blanket form even corrupted INTEGER precision to the impossible `precision=23`
/// (real ints are always 0). Passing through returns the real, self-consistent values
/// with no own-property tell.
pub(crate) fn webgl_shape_js() -> String {
    r#"(function() {
    try {
        function patch(proto) {
            if (!proto) return;
            if (proto.getSupportedExtensions) {
                const origExtensions = proto.getSupportedExtensions;
                proto.getSupportedExtensions = __seal(function() {
                    const list = origExtensions.call(this) || [];
                    if (!list.includes('WEBGL_debug_renderer_info')) {
                        list.push('WEBGL_debug_renderer_info');
                    }
                    return list;
                }, 'getSupportedExtensions');
            }
        }
        if (typeof WebGLRenderingContext !== 'undefined') patch(WebGLRenderingContext.prototype);
        if (typeof WebGL2RenderingContext !== 'undefined') patch(WebGL2RenderingContext.prototype);
    } catch (_) {}
})()"#
        .to_string()
}
