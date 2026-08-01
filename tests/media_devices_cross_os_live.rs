//! Live PoC: what does a guise persona expose via
//! `navigator.mediaDevices.enumerateDevices()`?
//!
//! Real desktop browsers expose >=1 audioinput + >=1 audiooutput (Chrome also
//! exposes audiooutput; FF historically did not by default). A HEADLESS browser
//! with no audio hardware can return an EMPTY list, a strong bot signal, and on
//! a real machine the device labels/groupIds are host-specific (a fingerprint and
//! a potential cross-OS tell: "Realtek…"/"MME" vs "Built-in Audio"/ALSA).
//!
//! guise ships a Tier-B audio-device persona library (`audio_device_tier_b.rs`,
//! G098) whose module doc says it exists to present a coherent set via
//! `enumerateDevices()`: but `AudioDevicePersona` is referenced ONLY by its own
//! module + tests: there is NO builtin set, NO JS-emit, and the apply path never
//! consumes it, so `enumerateDevices()` is currently NOT spoofed and a persona
//! returns the host's real list. This test MEASURES the live behaviour (bare vs
//! persona) so the disposition is known and pinned: it documents whether the
//! proxyless headless persona presents an enumerateDevices tell. When the Tier-B
//! library is wired to emit an override, the bare-vs-persona equality flips
//! intentional, update the disposition then.
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
        eprintln!("skip media_devices_cross_os_live: set STEALTH_LIVE_BROWSER=1");
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
    // 127.0.0.1 is a secure context in Firefox, so navigator.mediaDevices is present.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body = b"<!doctype html><html><body>md</body></html>";
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

// Returns each device's kind + whether label/deviceId/groupId are populated. We
// deliberately do NOT print raw labels/ids (they can carry host identifiers); the
// SHAPE (kind set, emptiness) is the fingerprint-relevant part pre-permission.
const PROBE: &str = r#"
navigator.mediaDevices && navigator.mediaDevices.enumerateDevices
  ? navigator.mediaDevices.enumerateDevices().then(function(list){
      return JSON.stringify(list.map(function(d){
        return { kind: d.kind,
                 labelLen: (d.label||'').length,
                 deviceId: d.deviceId === '' ? 'EMPTY' : (d.deviceId === 'default' ? 'default' : 'SET'),
                 groupId: (d.groupId||'') === '' ? 'EMPTY' : 'SET' };
      }));
    }).catch(function(e){ return JSON.stringify([{err:String(e)}]); })
  : Promise.resolve(JSON.stringify([{err:'no-mediaDevices'}]))
"#;

async fn devices_bare(url: &str) -> Vec<Value> {
    let page = launch_firefox_self_managed(cfg())
        .await
        .expect("bare launch");
    page.goto(url).await.expect("bare nav");
    let raw = page
        .evaluate_await(PROBE)
        .await
        .expect("bare eval")
        .into_value::<String>()
        .expect("bare json");
    let _ = page.close().await;
    serde_json::from_str(&raw).expect("bare parse")
}

async fn devices_persona(profile: &StealthProfile, url: &str) -> Vec<Value> {
    let page = guise::browser::launch_profiled_firefox(cfg(), profile)
        .await
        .expect("persona launch");
    page.goto(url).await.expect("persona nav");
    let raw = page
        .evaluate_await(PROBE)
        .await
        .expect("persona eval")
        .into_value::<String>()
        .expect("persona json");
    let _ = page.close().await;
    serde_json::from_str(&raw).expect("persona parse")
}

fn kinds(devs: &[Value]) -> Vec<String> {
    let mut k: Vec<String> = devs
        .iter()
        .filter_map(|d| d["kind"].as_str().map(|s| s.to_string()))
        .collect();
    k.sort();
    k
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enumerate_devices_disposition_bare_vs_persona() {
    if skip() {
        return;
    }
    let url = serve_origin().await;

    let bare = devices_bare(&url).await;
    let windows = devices_persona(&StealthProfile::FirefoxWindows, &url).await;
    let linux = devices_persona(&StealthProfile::FirefoxLinux, &url).await;

    let report = format!(
        "HOST OS: {}\nBARE   ({} devs) kinds={:?}\n  {:?}\nWINDOWS({} devs) kinds={:?}\n  {:?}\nLINUX  ({} devs) kinds={:?}\n  {:?}\n",
        std::env::consts::OS,
        bare.len(), kinds(&bare), bare,
        windows.len(), kinds(&windows), windows,
        linux.len(), kinds(&linux), linux,
    );
    let _ = std::fs::write("/tmp/guise_media_devices.txt", &report);
    eprint!("{report}");

    // Probe sanity: mediaDevices.enumerateDevices must be reachable (secure context).
    assert!(
        !bare.iter().any(|d| d.get("err").is_some()),
        "bare enumerateDevices probe errored: {bare:?}"
    );
    assert!(
        !windows.iter().any(|d| d.get("err").is_some()),
        "windows enumerateDevices probe errored: {windows:?}"
    );

    // CURRENT DISPOSITION (enumerateDevices is NOT spoofed): a persona inherits the
    // host's device SHAPE, the kind multiset is identical to bare. Pinning this
    // makes the wiring of audio_device_tier_b a deliberate, test-visible change.
    assert_eq!(
        kinds(&windows),
        kinds(&bare),
        "FirefoxWindows enumerateDevices kinds diverged from bare, enumerateDevices \
         spoofing now present? Wire/disposition changed; update this test and \
         audio_device_tier_b accordingly. windows={windows:?} bare={bare:?}"
    );
    assert_eq!(
        kinds(&linux),
        kinds(&bare),
        "FirefoxLinux enumerateDevices kinds diverged from bare: linux={linux:?} bare={bare:?}"
    );
}
