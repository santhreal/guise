//! Live contract: a cross-OS persona must not leak the host OS's speechSynthesis
//! voice list.
//!
//! `speechSynthesis.getVoices()` exposes the host TTS voices, which are strongly
//! OS-correlated (a Linux espeak-ng set of thousands, a Windows SAPI set, an Apple
//! set). A cross-OS persona that leaves the host list is a screaming tell
//! confirmed live (dump_speech_and_datezone_truth: a FirefoxWindows persona on this
//! Linux host exposed ~13k espeak voices under a Windows UA). The fix suppresses the
//! list (getVoices()->[]) for cross-OS personas while matched personas keep the
//! native, coherent list.
//!
//! Host-robust: if the host itself has no voices (a CI box without TTS), the
//! suppression is a no-op and the "did suppression change anything" check is
//! skipped; the cross-OS-returns-empty and matched-equals-bare invariants still hold.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1 [STEALTH_FIREFOX=/path]` (spawns real Firefox).
#![cfg(feature = "browser")]

use guise::fingerprint::StealthProfile;
use runtime_foxdriver::{launch_firefox, FoxBrowserConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn skip() -> bool {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("skip speech_cross_os_live: set STEALTH_LIVE_BROWSER=1 (spawns real Firefox)");
        return true;
    }
    false
}

async fn serve_secure_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body =
                    b"<!doctype html><html><head><title>s</title></head><body>x</body></html>";
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

/// Resolves to the voice count after giving async voice loading a moment.
const VOICE_COUNT: &str = r#"(function(){
  return new Promise(function(resolve){
    function n(){ try { return (speechSynthesis.getVoices()||[]).length; } catch(e){ return -1; } }
    if (n() > 0) { resolve(String(n())); return; }
    try { speechSynthesis.onvoiceschanged = function(){ resolve(String(n())); }; } catch(e){}
    setTimeout(function(){ resolve(String(n())); }, 1500);
  });
})()"#;

async fn voices(page: &runtime_foxdriver::browser::Page, url: &str) -> i64 {
    page.goto(url).await.expect("nav");
    page.evaluate_await(VOICE_COUNT)
        .await
        .expect("eval VOICE_COUNT")
        .into_value::<String>()
        .expect("string")
        .parse::<i64>()
        .expect("count")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_os_persona_does_not_leak_host_voice_list() {
    if skip() {
        return;
    }
    let mut cfg = FoxBrowserConfig {
        headless: true,
        ..Default::default()
    };
    if let Ok(p) = std::env::var("STEALTH_FIREFOX") {
        cfg.executable_path = Some(p);
    }
    let url = serve_secure_origin().await;

    let bare = launch_firefox(cfg.clone()).await.expect("launch bare");
    let bare_voices = voices(&bare, &url).await;
    let _ = bare.close().await;

    let win_page =
        guise::browser::launch_profiled_firefox(cfg.clone(), &StealthProfile::FirefoxWindows)
            .await
            .expect("launch windows persona");
    let win_voices = voices(&win_page, &url).await;
    let _ = win_page.close().await;

    let lin_page = guise::browser::launch_profiled_firefox(cfg, &StealthProfile::FirefoxLinux)
        .await
        .expect("launch linux persona");
    let lin_voices = voices(&lin_page, &url).await;
    let _ = lin_page.close().await;

    eprintln!("voices: bare={bare_voices} windows={win_voices} linux={lin_voices}");

    // Cross-OS Windows persona must expose NO voices (host list suppressed).
    assert_eq!(
        win_voices, 0,
        "Windows persona leaked a voice list (bare had {bare_voices})"
    );
    // Matched Linux persona keeps the native list (== bare on this host).
    assert_eq!(
        lin_voices, bare_voices,
        "matched Linux persona must keep the native voice list"
    );
    // If the host actually has voices, the suppression must have changed something
    // (otherwise the win==0 assertion above could pass vacuously on a TTS-less box).
    if bare_voices > 0 {
        assert_ne!(
            win_voices, bare_voices,
            "Windows suppression had no effect though the host has voices"
        );
    }
}
