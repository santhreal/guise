//! Lie-detector live regression (G194).
//!
//! Spawns a real Firefox (reynard/stock) and runs the lie-detector probe from
//! the Firefox-family catalogue. A clean, un-spoofed browser must produce zero
//! lies (ProbeOutcome::Pass); any lie is a detection signal.
//!
//! Opt-in: `STEALTH_LIVE_BROWSER=1`.
#![cfg(feature = "browser")]

use guise::probe::{run_for, UserAgentBrowser};
use runtime_foxdriver::{launch_firefox, FoxBrowserConfig};

const PAGE: &str = r#"<!doctype html><html><body>ok</body></html>"#;

async fn serve() -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = PAGE.as_bytes().to_vec();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes())
                    .await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    format!("http://{addr}/")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stock_firefox_has_zero_lie_detector_flags() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!("SKIP lie_detector_live: set STEALTH_LIVE_BROWSER=1 to run (spawns Firefox)");
        return;
    }
    let url = serve().await;
    let page = launch_firefox(FoxBrowserConfig {
        headless: true,
        ..Default::default()
    })
    .await
    .expect("launch for lie detector");
    page.goto(&url).await.expect("navigate");

    let report = run_for(&page, UserAgentBrowser::Firefox)
        .await
        .expect("run probe catalogue");
    let lie_probe = report
        .per_probe
        .iter()
        .find(|p| p.name == "lie-detector: descriptor / toString inconsistencies")
        .expect("lie-detector probe present in catalogue");
    assert!(
        lie_probe.outcome.is_pass(),
        "lie detector flagged a real Firefox: {:?}",
        lie_probe.outcome
    );

    let _ = page.close().await;
}
