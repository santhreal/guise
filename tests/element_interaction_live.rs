//! DOM-aware interaction regression (live Firefox).
//!
//! Proves the human-mouse layer respects real page geometry and semantics:
//! - it lands on a non-center point inside visible elements (G161/G162);
//! - it hovers before clicking (G163);
//! - it refuses to interact with hidden, disabled, or zero-size elements
//!   (G165/G166).
//!
//! Opt-in (spawns a real Firefox): `STEALTH_LIVE_BROWSER=1`.
#![cfg(feature = "browser")]

use guise::human::{assert_interactable, ElementBox, HumanMouse, MousePersona};
use runtime_foxdriver::{launch_firefox, FoxBrowserConfig, Page};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PAGE: &str = r#"<!doctype html>
<html><body>
<button id="ok" style="width:200px;height:80px">OK</button>
<button id="disabled" disabled style="width:200px;height:80px">Disabled</button>
<button id="hidden" style="display:none;width:200px;height:80px">Hidden</button>
<button id="zero" style="width:0;height:0;border:0;padding:0">Zero</button>
</body></html>"#;

async fn serve() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = PAGE.as_bytes();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let body = body.to_vec();
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

async fn visible_rect(page: &Page, selector: &str) -> ElementBox {
    let expr = format!(
        "(function(){{ const r = document.querySelector({:?}).getBoundingClientRect(); return {{x:r.x,y:r.y,width:r.width,height:r.height}}; }})()",
        selector
    );
    page.evaluate(expr)
        .await
        .expect("evaluate rect")
        .into_value::<ElementBox>()
        .expect("deserialize rect")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interactable_guard_rejects_bad_elements() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!(
            "SKIP element_interaction_live: set STEALTH_LIVE_BROWSER=1 to run (spawns Firefox)"
        );
        return;
    }
    let url = serve().await;
    let page = launch_firefox(FoxBrowserConfig {
        headless: true,
        ..Default::default()
    })
    .await
    .expect("launch for element interaction");
    page.goto(&url).await.expect("navigate");

    // Visible element is accepted.
    assert!(assert_interactable(&page, "#ok").await.is_ok());

    // Disabled, hidden, and zero-size elements are rejected.
    assert!(assert_interactable(&page, "#disabled").await.is_err());
    assert!(assert_interactable(&page, "#hidden").await.is_err());
    assert!(assert_interactable(&page, "#zero").await.is_err());
    assert!(assert_interactable(&page, "#missing").await.is_err());

    let _ = page.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn click_element_lands_inside_target_and_updates_cursor() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!(
            "SKIP element_interaction_live: set STEALTH_LIVE_BROWSER=1 to run (spawns Firefox)"
        );
        return;
    }
    let url = serve().await;
    let page = launch_firefox(FoxBrowserConfig {
        headless: true,
        ..Default::default()
    })
    .await
    .expect("launch for element interaction");
    page.goto(&url).await.expect("navigate");

    let mut mouse = HumanMouse::new(MousePersona::Normal);
    mouse.click_element(&page, "#ok").await.expect("click ok");

    let rect = visible_rect(&page, "#ok").await;
    assert!(
        mouse.cursor_x >= rect.x && mouse.cursor_x <= rect.x + rect.width,
        "cursor x {} outside target",
        mouse.cursor_x
    );
    assert!(
        mouse.cursor_y >= rect.y && mouse.cursor_y <= rect.y + rect.height,
        "cursor y {} outside target",
        mouse.cursor_y
    );
    // Cursor should not be the exact center on a 200x80 button.
    let (cx, cy) = rect.center();
    let exact_center = (mouse.cursor_x - cx).abs() < 1.0 && (mouse.cursor_y - cy).abs() < 1.0;
    assert!(
        !exact_center,
        "click landed at exact center, distribution is broken"
    );

    let _ = page.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hover_then_click_element_works() {
    if std::env::var("STEALTH_LIVE_BROWSER").is_err() {
        eprintln!(
            "SKIP element_interaction_live: set STEALTH_LIVE_BROWSER=1 to run (spawns Firefox)"
        );
        return;
    }
    let url = serve().await;
    let page = launch_firefox(FoxBrowserConfig {
        headless: true,
        ..Default::default()
    })
    .await
    .expect("launch for element interaction");
    page.goto(&url).await.expect("navigate");

    let mut mouse = HumanMouse::new(MousePersona::Careful);
    mouse
        .hover_then_click_element(&page, "#ok")
        .await
        .expect("hover then click ok");

    let _ = page.close().await;
}
