//! Live DIAGNOSTIC: canvas determinism across restarts on a REAL http content
//! origin (not about:blank), bare engine vs full stealth.
//!
//! Probes A–D in canvas_base_determinism_live show the canvas is stable across
//! restarts on `about:blank`. The persistence test drifts on a real http origin
//! with the SAME profile seed, for BOTH ASCII and emoji text. This isolates the
//! cause: if the BARE engine (no guise farble) ALSO drifts on a real origin, the
//! nondeterminism is a Firefox canvas/GPU-readback property the JS farble cannot
//! fix (reynard/engine-level is the determinism path, and real users see the same
//! variance). If bare is STABLE but stealth DRIFTS, the farble introduces it on
//! real origins and that is a guise bug.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]`.
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::browser::launch_firefox_self_managed;
use runtime_foxdriver::FoxBrowserConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip canvas_real_origin_live: set STEALTH_LIVE_BROWSER=1");
        return true;
    }
    false
}

async fn serve() -> (String, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    (format!("http://{addr}/"), listener)
}

async fn pump(listener: TcpListener) {
    while let Ok((mut sock, _)) = listener.accept().await {
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let body = b"<!doctype html><html><head><title>c</title></head><body>x</body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.shutdown().await;
        });
    }
}

const HASH: &str = r#"(function(){
  try {
    var c = document.createElement('canvas'); c.width=200; c.height=50;
    var x = c.getContext('2d');
    x.textBaseline='top'; x.font='14px Arial'; x.fillStyle='#069'; x.fillText('guise-persist-Cwm fjordbank', 2, 2);
    var d = c.toDataURL();
    var h = 0; for (var i=0;i<d.length;i++){ h=((h<<5)-h+d.charCodeAt(i))|0; }
    return d.length + ':' + String(h);
  } catch(e){ return 'ERR:'+e; }
})()"#;

fn base_cfg(profile_dir: &str) -> FoxBrowserConfig {
    let mut c = FoxBrowserConfig {
        headless: true,
        profile_dir: Some(profile_dir.to_string()),
        ..Default::default()
    };
    if let Ok(p) = std::env::var("STEALTH_FIREFOX") {
        c.executable_path = Some(p);
    }
    c
}

async fn bare(url: &str, profile_dir: &str) -> String {
    let page = launch_firefox_self_managed(base_cfg(profile_dir))
        .await
        .expect("bare");
    page.goto(url).await.expect("nav");
    let h = page
        .evaluate(HASH)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("s");
    let _ = page.close().await;
    h
}

async fn stealth(url: &str, profile_dir: &str) -> String {
    let page = guise::browser::launch_profiled_firefox(
        base_cfg(profile_dir),
        &StealthProfile::FirefoxLinux,
    )
    .await
    .expect("stealth");
    page.goto(url).await.expect("nav");
    let h = page
        .evaluate(HASH)
        .await
        .expect("eval")
        .into_value::<String>()
        .expect("s");
    let _ = page.close().await;
    h
}

fn fresh(tag: &str) -> String {
    let d = std::env::temp_dir()
        .join(format!("guise-realorigin-{tag}-{}", std::process::id()))
        .display()
        .to_string();
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canvas_real_origin_determinism() {
    if skip() {
        return;
    }
    let (url, listener) = serve().await;
    tokio::spawn(pump(listener));

    let db = fresh("bare");
    let b1 = bare(&url, &db).await;
    let b2 = bare(&url, &db).await;
    let _ = std::fs::remove_dir_all(&db);

    let ds = fresh("stealth");
    let s1 = stealth(&url, &ds).await;
    let s2 = stealth(&url, &ds).await;
    let _ = std::fs::remove_dir_all(&ds);

    let report = format!(
        "BARE real-origin   : {b1} | {b2} | {}\nSTEALTH real-origin: {s1} | {s2} | {}\n",
        if b1 == b2 { "STABLE" } else { "DRIFT" },
        if s1 == s2 { "STABLE" } else { "DRIFT" },
    );
    let _ = std::fs::write("/tmp/guise_canvas_realorigin.txt", &report);
    eprint!("{report}");

    // Minimal teeth so this investigative probe can't silently rot: the canvas must
    // RENDER (non-ERR, non-empty) on every launch under both bare and stealth. The
    // cross-restart drift itself is the documented finding (engine/GPU readback,
    // bare drifts too (see this file's module docs); it is reported, not asserted).
    for (tag, h) in [
        ("bare1", &b1),
        ("bare2", &b2),
        ("stealth1", &s1),
        ("stealth2", &s2),
    ] {
        assert!(
            !h.starts_with("ERR") && !h.is_empty(),
            "{tag} canvas failed to render: {h}"
        );
    }
}
