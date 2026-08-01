//! Live PoC: a cross-OS persona's WebGL DEEP PARAMETERS betray the real GPU/driver.
//!
//! `webgl_cross_os_live.rs` proves the WebGL renderer/vendor STRINGS cohere with
//! the persona OS (Windows → an ANGLE/Direct3D adapter, masked == unmasked, no host
//! GPU leak). But a real WebGL fingerprint (CreepJS, FingerprintJS) hashes far more
//! than the strings: `getSupportedExtensions()`, the `MAX_*` numeric limits, and
//! `getShaderPrecisionFormat()`. guise's `webgl_shape_js` only APPENDS
//! `WEBGL_debug_renderer_info` (and leaves shader precision NATIVE/pass-through), it
//! does NOT rewrite the extension list or the limits. So on a cross-OS persona those
//! come straight from
//! the host GL driver: the renderer claims `ANGLE (… Direct3D11 …)` (a Windows-only
//! GL→D3D11 layer) while the extension set and limits are the Linux host driver's
//! a hard contradiction (ANGLE/D3D11 exposes a DIFFERENT extension list and limits
//! than Linux Mesa).
//!
//! This is NOT soundly JS-spoofable: claiming an extension the real driver lacks
//! fails the instant a detector calls `getExtension()` on it (it returns null while
//! the list advertised it), and faking a larger `MAX_TEXTURE_SIZE` than the driver
//! supports fails at allocation, a behavioural oracle disproves the lie. It is an
//! ENGINE-rendered residual in the same class as font enumeration; reynard governs
//! the GL backend at the engine level. This test PINS the residual's existence (so
//! `surface_cross_os_rendering_tell` keeps naming it) following the
//! font_cross_os_live methodology: compare each persona to the BARE engine on the
//! same host (a deep-param set equal to bare is the host truth leaking through).
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::browser::launch_firefox_self_managed;
use runtime_foxdriver::FoxBrowserConfig;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip webgl_deep_params_cross_os_live: set STEALTH_LIVE_BROWSER=1");
        return true;
    }
    false
}

fn cfg() -> FoxBrowserConfig {
    let mut c = FoxBrowserConfig {
        headless: true,
        ..Default::default()
    };
    if let Ok(p) = std::env::var("STEALTH_FIREFOX") {
        c.executable_path = Some(p);
    }
    c
}

async fn serve_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body = b"<!doctype html><html><body>gl</body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}/")
}

const PROBE: &str = r#"JSON.stringify((function(){
  try {
    var c = document.createElement('canvas');
    var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (!gl) return {err:'no-webgl'};
    var dbg = gl.getExtension('WEBGL_debug_renderer_info');
    var renderer = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)) : '';
    var exts = (gl.getSupportedExtensions()||[]).slice().sort();
    var P = function(n){ try { var v = gl.getParameter(gl[n]); return v && v.length !== undefined ? Array.from(v) : v; } catch(e){ return 'ERR'; } };
    var limits = {
      MAX_TEXTURE_SIZE: P('MAX_TEXTURE_SIZE'),
      MAX_CUBE_MAP_TEXTURE_SIZE: P('MAX_CUBE_MAP_TEXTURE_SIZE'),
      MAX_RENDERBUFFER_SIZE: P('MAX_RENDERBUFFER_SIZE'),
      MAX_VIEWPORT_DIMS: P('MAX_VIEWPORT_DIMS'),
      MAX_VERTEX_ATTRIBS: P('MAX_VERTEX_ATTRIBS'),
      MAX_VERTEX_UNIFORM_VECTORS: P('MAX_VERTEX_UNIFORM_VECTORS'),
      MAX_VARYING_VECTORS: P('MAX_VARYING_VECTORS'),
      MAX_FRAGMENT_UNIFORM_VECTORS: P('MAX_FRAGMENT_UNIFORM_VECTORS'),
      MAX_TEXTURE_IMAGE_UNITS: P('MAX_TEXTURE_IMAGE_UNITS'),
      MAX_COMBINED_TEXTURE_IMAGE_UNITS: P('MAX_COMBINED_TEXTURE_IMAGE_UNITS'),
      ALIASED_LINE_WIDTH_RANGE: P('ALIASED_LINE_WIDTH_RANGE'),
      ALIASED_POINT_SIZE_RANGE: P('ALIASED_POINT_SIZE_RANGE')
    };
    function prec(t,p){ try { var r = gl.getShaderPrecisionFormat(gl[t], gl[p]); return r ? [r.precision, r.rangeMin, r.rangeMax] : null; } catch(e){ return 'ERR'; } }
    function precOwn(t,p){ try { var r = gl.getShaderPrecisionFormat(gl[t], gl[p]); return r ? [r.hasOwnProperty('precision'), r.hasOwnProperty('rangeMin'), r.hasOwnProperty('rangeMax')] : null; } catch(e){ return 'ERR'; } }
    var precision = {
      HIGH_FLOAT: prec('FRAGMENT_SHADER','HIGH_FLOAT'),
      HIGH_INT: prec('FRAGMENT_SHADER','HIGH_INT')
    };
    var precisionOwn = {
      HIGH_FLOAT: precOwn('FRAGMENT_SHADER','HIGH_FLOAT'),
      HIGH_INT: precOwn('FRAGMENT_SHADER','HIGH_INT')
    };
    return {renderer:renderer, exts:exts, limits:limits, precision:precision, precisionOwn:precisionOwn};
  } catch(e){ return {err:String(e)}; }
})())"#;

async fn probe_bare(url: &str) -> Value {
    let page = launch_firefox_self_managed(cfg())
        .await
        .expect("bare launch");
    page.goto(url).await.expect("bare nav");
    let raw = page
        .evaluate(PROBE)
        .await
        .expect("bare eval")
        .into_value::<String>()
        .expect("bare json");
    let _ = page.close().await;
    serde_json::from_str(&raw).expect("bare parse")
}

async fn probe_persona(profile: &StealthProfile, url: &str) -> Value {
    let page = guise::browser::launch_profiled_firefox(cfg(), profile)
        .await
        .expect("persona launch");
    page.goto(url).await.expect("persona nav");
    let raw = page
        .evaluate(PROBE)
        .await
        .expect("persona eval")
        .into_value::<String>()
        .expect("persona json");
    let _ = page.close().await;
    serde_json::from_str(&raw).expect("persona parse")
}

/// Extension list as a sorted `Vec<String>` with `WEBGL_debug_renderer_info`
/// removed, that one is APPENDED by guise's `webgl_shape_js` (so the renderer
/// spoof's extension is always present) and would otherwise be the only diff
/// between bare and a persona. Removing it isolates the DRIVER's own list.
fn ext_set(v: &Value) -> Vec<String> {
    let mut e: Vec<String> = v["exts"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .filter(|s| *s != "WEBGL_debug_renderer_info")
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();
    e.sort();
    e
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_os_persona_webgl_deep_params_equal_the_bare_host_driver() {
    if skip() {
        return;
    }
    let url = serve_origin().await;

    let bare = probe_bare(&url).await;
    let windows = probe_persona(&StealthProfile::FirefoxWindows, &url).await;

    let report = format!(
        "HOST OS: {}\nBARE renderer    : {}\nWINDOWS renderer : {}\nBARE limits    : {}\nWINDOWS limits : {}\nBARE exts({})  WINDOWS exts({})\nBARE precision    : {} own={}\nWINDOWS precision : {} own={}\n",
        std::env::consts::OS,
        bare["renderer"], windows["renderer"],
        bare["limits"], windows["limits"],
        ext_set(&bare).len(), ext_set(&windows).len(),
        bare["precision"], bare["precisionOwn"], windows["precision"], windows["precisionOwn"],
    );
    let _ = std::fs::write("/tmp/guise_webgl_deep_params.txt", &report);
    eprint!("{report}");

    // Probe sanity: WebGL must be present on both arms.
    assert!(bare.get("err").is_none(), "bare WebGL probe failed: {bare}");
    assert!(
        windows.get("err").is_none(),
        "windows WebGL probe failed: {windows}"
    );

    // This disposition is asserted for a cross-OS run (host != windows). On a
    // Windows host the persona is matched and these comparisons are vacuous.
    if std::env::consts::OS != "windows" {
        let bare_r = bare["renderer"].as_str().unwrap_or("");
        let win_r = windows["renderer"].as_str().unwrap_or("");

        // The STRING spoof works: the persona claims a Windows ANGLE/Direct3D
        // adapter, the bare host does not.
        assert!(
            win_r.contains("ANGLE") || win_r.contains("Direct3D"),
            "FirefoxWindows persona renderer must claim an ANGLE/Direct3D adapter, got {win_r:?}"
        );
        assert!(
            !(bare_r.contains("ANGLE") || bare_r.contains("Direct3D")),
            "bare Linux engine unexpectedly reports an ANGLE/Direct3D renderer ({bare_r:?}). \
             probe/methodology assumption broken"
        );

        // THE RESIDUAL: despite the ANGLE/D3D11 renderer claim, the deep-parameter
        // surface is byte-identical to the bare host driver, proving it is the
        // Linux GL driver's, not ANGLE's. A real Windows ANGLE context would expose
        // a different extension list and different limits.
        assert_eq!(
            ext_set(&windows),
            ext_set(&bare),
            "WebGL extension list diverged from bare, engine-level GL masking now present? \
             Update the cross-OS WebGL disposition in surface_cross_os_rendering_tell."
        );
        assert_eq!(
            windows["limits"], bare["limits"],
            "WebGL MAX_* limits diverged from bare, engine-level GL masking now present? \
             Update the cross-OS WebGL disposition in surface_cross_os_rendering_tell."
        );
    }

    // Independent of OS: getShaderPrecisionFormat is now PASS-THROUGH (left native).
    // Every value matches bare, AND there is no own-property descriptor lie. (Earlier
    // this path normalized via Object.defineProperty(result,...) which both corrupted
    // INTEGER precision to the impossible precision=23 AND created own data properties
    // real Firefox lacks, result.hasOwnProperty('precision') flipped true.)
    assert_eq!(
        windows["precision"], bare["precision"],
        "persona shader precision diverged from the real driver value (must be \
         pass-through): persona={} bare={}",
        windows["precision"], bare["precision"]
    );
    // Hard teeth on the integer bug: highp INT precision component is 0 on real
    // hardware (ints have no mantissa) (a non-zero value is impossible).
    assert_eq!(
        windows["precision"]["HIGH_INT"][0],
        serde_json::json!(0),
        "persona highp-INT reports a non-zero precision (impossible on real hardware): {}",
        windows["precision"]
    );
    // Descriptor coherence: precision/rangeMin/rangeMax are PROTOTYPE getters on real
    // FF, never own properties. The persona must not create own data props (the tell
    // the old normalization introduced). Asserted == bare so a future FF that changes
    // the shape does not make the test lie.
    assert_eq!(
        windows["precisionOwn"], bare["precisionOwn"],
        "persona WebGLShaderPrecisionFormat own-property shape diverged from bare, an \
         own-property descriptor tell: persona={} bare={}",
        windows["precisionOwn"], bare["precisionOwn"]
    );
    assert_eq!(
        bare["precisionOwn"]["HIGH_FLOAT"],
        serde_json::json!([false, false, false]),
        "sanity: real FF must expose shader precision via PROTOTYPE getters (no own \
         props), contract assumption: {}",
        bare["precisionOwn"]
    );
}
