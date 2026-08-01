use super::*;
use std::time::Instant;

#[tokio::test]
async fn random_pause_returns_within_window() {
    let start = Instant::now();
    random_pause(50, 80).await;
    let elapsed_ms = start.elapsed().as_millis() as u64;
    // Allow a generous +50ms scheduler tolerance - tokio sleeps
    // are "at least", not "exactly".
    assert!(
        (50..=130).contains(&elapsed_ms),
        "random_pause(50, 80) elapsed {elapsed_ms}ms (expected 50..=130)"
    );
}

#[tokio::test]
async fn random_pause_with_equal_bounds_does_not_panic() {
    let start = Instant::now();
    random_pause(40, 40).await;
    let elapsed_ms = start.elapsed().as_millis() as u64;
    assert!(elapsed_ms >= 40);
}

#[tokio::test]
#[should_panic(expected = "ActionDelay::uniform: min_ms")]
async fn random_pause_panics_when_min_exceeds_max() {
    random_pause(200, 100).await;
}
