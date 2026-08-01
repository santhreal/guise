//! Live characterization: WebGPU (`navigator.gpu`) cross-OS coherence.
//!
//! WebGPU is a modern, high-weight GPU fingerprint: `navigator.gpu.requestAdapter()
//! .info` exposes vendor/architecture/device, and the adapter limits mirror the real
//! GPU/driver: OS-correlated just like WebGL, but newer and rarely spoofed. guise
//! does NOT touch `navigator.gpu` (only `surface.rs` catalogs it). Two cross-OS tells
//! are possible and this measures which applies on the fleet:
//!   (a) PRESENCE mismatch, a real Windows Firefox (WebGPU on by default since FF
//!       141) HAS `navigator.gpu`; if the Linux host has it OFF, a FirefoxWindows
//!       persona LACKS it → a tell.
//!   (b) ADAPTER leak, if present, `adapter.info` / limits report the host GPU
//!       (e.g. NVIDIA on this Linux box) under the Windows persona → a cross-OS leak.
//!
//! This reports the live state (bare vs persona) and asserts the persona is COHERENT
//! with bare presence-wise (guise doesn't add/remove navigator.gpu), pinning the
//! disposition so a future spoof or an engine default-flip is visible.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::browser::{launch_firefox_self_managed, Page};
use runtime_foxdriver::FoxBrowserConfig;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip webgpu_cross_os_live: set STEALTH_LIVE_BROWSER=1");
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
                let body = b"<!doctype html><html><body>gpu</body></html>";
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

const PROBE: &str = r#"(function(){
  return new Promise(function(resolve){
    var done=false;
    function R(o){ if(!done){done=true; resolve(JSON.stringify(o));} }
    if (!('gpu' in navigator) || !navigator.gpu) { R({present:false}); return; }
    try {
      navigator.gpu.requestAdapter().then(function(a){
        if (!a) { R({present:true, adapter:null}); return; }
        var lim = a.limits ? a.limits.maxTextureDimension2D : null;
        function emit(i){ i=i||{}; R({present:true, adapter:true,
          vendor:i.vendor, architecture:i.architecture, device:i.device, description:i.description,
          maxTextureDimension2D: lim }); }
        if (a.info) emit(a.info);
        else if (a.requestAdapterInfo) a.requestAdapterInfo().then(emit).catch(function(e){ R({present:true,adapter:true,err:String(e)}); });
        else R({present:true, adapter:true, noinfo:true});
      }).catch(function(e){ R({present:true, err:String(e)}); });
    } catch(e){ R({present:true, err:'throw:'+e}); }
    setTimeout(function(){ R({present:true, timeout:true}); }, 6000);
  });
})()"#;

async fn webgpu(page: Page, url: &str) -> Value {
    page.goto(url).await.expect("nav");
    let raw = page
        .evaluate_await(PROBE)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("json");
    let _ = page.close().await;
    serde_json::from_str(&raw).expect("parse")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webgpu_cross_os_disposition() {
    if skip() {
        return;
    }
    let url = serve_origin().await;
    let bare = webgpu(
        launch_firefox_self_managed(cfg()).await.expect("bare"),
        &url,
    )
    .await;
    let win = webgpu(
        guise::browser::launch_profiled_firefox(cfg(), &StealthProfile::FirefoxWindows)
            .await
            .expect("persona"),
        &url,
    )
    .await;

    let report = format!(
        "HOST OS: {}\nBARE:    {bare}\nWINDOWS: {win}\n",
        std::env::consts::OS
    );
    let _ = std::fs::write("/tmp/guise_webgpu_cross_os.txt", &report);
    eprint!("{report}");

    // Coherence pin: guise does not add/remove navigator.gpu, so the persona's
    // presence matches bare. (If they diverge, a spoof or engine flip happened
    // revisit the WebGPU disposition.)
    assert_eq!(
        win["present"], bare["present"],
        "navigator.gpu presence diverged from bare (guise must not add/remove it): {report}"
    );

    // Document the cross-OS exposure with teeth WHERE it manifests on this host:
    if std::env::consts::OS != "windows" {
        if win["present"] == Value::Bool(false) {
            // PRESENCE-tell case: a real Windows FF has WebGPU; this persona lacks it.
            // Pin it so closing the residual (engine-level WebGPU enable+spoof) is visible.
            eprintln!(
                "[webgpu disposition] FirefoxWindows persona LACKS navigator.gpu while a real \
                 Windows FF (WebGPU default-on since 141) has it, a cross-OS presence tell. \
                 Engine-conditional surface; reynard/engine must enable+spoof WebGPU to close it."
            );
        } else if win.get("adapter") == Some(&Value::Bool(true)) {
            // ADAPTER-leak case: the adapter info must NOT carry a host-GPU token that
            // contradicts the Windows persona (e.g. the Linux NVIDIA/Mesa adapter).
            let blob = win.to_string().to_lowercase();
            eprintln!(
                "[webgpu disposition] navigator.gpu PRESENT on the persona; adapter info: {win}"
            );
            assert!(
                !blob.contains("nvidia") && !blob.contains("mesa") && !blob.contains("llvmpipe"),
                "WebGPU adapter info leaks the host GPU under a Windows persona, a cross-OS \
                 leak guise does not yet spoof: {report}"
            );
        }
    }
}
