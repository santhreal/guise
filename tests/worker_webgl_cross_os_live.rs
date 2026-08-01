//! Live PoC: does a WORKER's OffscreenCanvas WebGL leak the host GPU on a cross-OS
//! persona?
//!
//! guise spoofs the WebGL UNMASKED_RENDERER/VENDOR (and masked RENDERER) via a JS
//! `getParameter` override on `WebGLRenderingContext.prototype`: a WINDOW-realm
//! preload. A Web Worker creates WebGL via `OffscreenCanvas.getContext('webgl')` on a
//! SEPARATE prototype the window preload never patched, so a cross-OS persona's worker
//! should report the real host GPU (NVIDIA…) under a Windows UA while the window
//! reports the spoofed ANGLE/Direct3D string (a cross-realm + cross-OS tell).
//!
//! The fix (if confirmed) is engine-level: `webgl.override-unmasked-renderer` /
//! `webgl.override-unmasked-vendor` prefs reach every realm including workers.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::FoxBrowserConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip worker_webgl_cross_os_live: set STEALTH_LIVE_BROWSER=1");
        return true;
    }
    false
}

async fn serve() -> (String, TcpListener) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let a = l.local_addr().unwrap();
    (format!("http://{a}/"), l)
}

async fn pump(l: TcpListener) {
    while let Ok((mut s, _)) = l.accept().await {
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            let _ = s.read(&mut b).await;
            let body = b"<!doctype html><html><body>wg</body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.write_all(body).await;
            let _ = s.shutdown().await;
        });
    }
}

const PROBE: &str = r#"(function(){
  function read(gl){
    if(!gl) return {r:'nogl',v:'nogl'};
    var ext = gl.getExtension('WEBGL_debug_renderer_info');
    return {
      r: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : 'noext',
      v: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : 'noext',
      masked: gl.getParameter(gl.RENDERER)
    };
  }
  return new Promise((resolve)=>{
    try {
      var winCanvas = document.createElement('canvas');
      var win = read(winCanvas.getContext('webgl')||winCanvas.getContext('experimental-webgl'));
      var code = "self.onmessage=function(){"
        + "function read(gl){if(!gl)return{r:'nogl',v:'nogl'};"
        + "var ext=gl.getExtension('WEBGL_debug_renderer_info');"
        + "return{r:ext?gl.getParameter(ext.UNMASKED_RENDERER_WEBGL):'noext',"
        + "v:ext?gl.getParameter(ext.UNMASKED_VENDOR_WEBGL):'noext',"
        + "masked:gl.getParameter(gl.RENDERER)};}"
        + "var off=new OffscreenCanvas(64,64);"
        + "var gl=off.getContext('webgl')||off.getContext('experimental-webgl');"
        + "postMessage(JSON.stringify(read(gl)));};";
      var w = new Worker(URL.createObjectURL(new Blob([code],{type:'application/javascript'})));
      w.onmessage=function(e){ resolve(JSON.stringify({win:win, worker:JSON.parse(e.data)})); };
      w.onerror=function(e){ resolve('ERR:worker:'+(e.message||'unknown')); };
      w.postMessage('go');
      setTimeout(function(){ resolve('ERR:timeout'); }, 6000);
    } catch(e){ resolve('ERR:'+e); }
  });
})()"#;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_offscreen_webgl_cross_os() {
    if skip() {
        return;
    }
    let (url, listener) = serve().await;
    tokio::spawn(pump(listener));

    let page = guise::browser::launch_profiled_firefox(cfg(), &StealthProfile::FirefoxWindows)
        .await
        .expect("launch");
    page.goto(&url).await.expect("nav");
    let r = page
        .evaluate_await(PROBE)
        .await
        .expect("probe")
        .into_value::<String>()
        .expect("s");
    let _ = page.close().await;

    let report = format!("FirefoxWindows window+worker WebGL:\n{r}\n");
    let _ = std::fs::write("/tmp/guise_worker_webgl.txt", &report);
    eprint!("{report}");

    assert!(!r.starts_with("ERR"), "worker webgl probe failed: {r}");
    // If WebGL is unavailable in the worker (nogl/noext), there is nothing to leak
    // report-only. Otherwise the worker's UNMASKED_RENDERER must NOT be the host GPU
    // (NVIDIA, this host) under a Windows persona.
    if r.contains("\"r\":\"nogl\"") || r.contains("\"r\":\"noext\"") {
        eprintln!("NOTE: worker WebGL unavailable (nogl/noext), no leak surface here");
    } else {
        assert!(
            !r.contains("NVIDIA"),
            "worker OffscreenCanvas WebGL leaks the host GPU (NVIDIA) under a Windows persona: {r}"
        );
    }
}
