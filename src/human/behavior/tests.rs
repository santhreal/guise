#[test]
fn bezier_control_points_within_range() {
    let (x0, _y0) = (100.0, 200.0);
    let (x1, _y1) = (500.0, 400.0);
    let t0 = 0.0_f64;
    let t1 = 1.0_f64;
    let u0 = 1.0 - t0;
    let u1 = 1.0 - t1;
    let bx0 = u0.powi(3) * x0 + t0.powi(3) * x1;
    let bx1 = u1.powi(3) * x0 + t1.powi(3) * x1;
    assert!((bx0 - x0).abs() < 0.001);
    assert!((bx1 - x1).abs() < 0.001);
}

use super::*;

#[test]
fn scroll_direction_clone_copy() {
    let d = ScrollDirection::Down;
    let d2 = d;
    assert_eq!(d, d2);
}

#[test]
fn scroll_direction_debug() {
    let d = ScrollDirection::Up;
    assert!(format!("{:?}", d).contains("Up"));
}

#[test]
fn bezier_midpoint_t_0_5() {
    let x0 = 0.0;
    let y0 = 0.0;
    let x1 = 100.0;
    let y1 = 0.0;
    let cx1 = 25.0;
    let cy1 = 50.0;
    let cx2 = 75.0;
    let cy2 = 50.0;
    let t = 0.5;
    let u = 1.0 - t;
    let x = u * u * u * x0 + 3.0 * u * u * t * cx1 + 3.0 * u * t * t * cx2 + t * t * t * x1;
    let y = u * u * u * y0 + 3.0 * u * u * t * cy1 + 3.0 * u * t * t * cy2 + t * t * t * y1;
    assert!((x - 50.0_f64).abs() < 1.0);
    assert!((y - 37.5_f64).abs() < 1.0);
}

#[test]
fn bezier_is_linear_when_control_points_on_line() {
    let x0 = 0.0;
    let x1 = 100.0;
    let cx1 = 33.0;
    let cx2 = 66.0;
    for i in 0..=10 {
        let t = i as f64 / 10.0;
        let u = 1.0 - t;
        let x = u * u * u * x0 + 3.0 * u * u * t * cx1 + 3.0 * u * t * t * cx2 + t * t * t * x1;
        assert!((x - (t * 100.0)).abs() < 1.0, "t={} x={}", t, x);
    }
}

#[test]
fn ease_function_zero_at_endpoints() {
    let ease_0 = (std::f64::consts::PI * 0.0).sin();
    let ease_1 = (std::f64::consts::PI * 1.0).sin();
    assert!((ease_0).abs() < 0.001);
    assert!((ease_1).abs() < 0.001);
}

#[test]
fn ease_function_max_at_midpoint() {
    let ease = (std::f64::consts::PI * 0.5).sin();
    assert!((ease - 1.0).abs() < 0.001);
}

#[test]
fn bezier_formula_degenerate_case_same_point() {
    let x0 = 50.0;
    let x1 = 50.0;
    let cx1 = 50.0;
    let cx2 = 50.0;
    for i in 0..=10 {
        let t = i as f64 / 10.0;
        let u = 1.0 - t;
        let x = u * u * u * x0 + 3.0 * u * u * t * cx1 + 3.0 * u * t * t * cx2 + t * t * t * x1;
        assert!((x - 50.0).abs() < 0.001);
    }
}

// ── touch-swipe geometry (the continuous-drag fix) ──────────────────────────

#[test]
fn swipe_points_count_matches_steps() {
    let pts = swipe_points(0.0, 0.0, 280.0, 0.0, 25);
    assert_eq!(pts.len(), 25);
}

#[test]
fn swipe_points_land_exactly_on_target() {
    let pts = swipe_points(40.0, 200.0, 320.0, 260.0, 25);
    let (lx, ly) = *pts.last().unwrap();
    assert!(
        (lx - 320.0).abs() < 1e-9,
        "swipe must end exactly at target x, got {lx}"
    );
    assert!(
        (ly - 260.0).abs() < 1e-9,
        "swipe must end exactly at target y, got {ly}"
    );
}

#[test]
fn swipe_points_are_monotonic_and_continuous() {
    // Every point lies between the previous one and the target along the swipe
    // axis, proving a single continuous drag, NOT the old origin-reset sawtooth
    // (which produced points jumping back toward the start each sub-step).
    let (x0, x1) = (40.0_f64, 320.0_f64);
    let pts = swipe_points(x0, 0.0, x1, 0.0, 25);
    let mut prev = x0;
    for (x, _) in &pts {
        assert!(*x > prev - 1e-9, "swipe x went backwards: {x} after {prev}");
        assert!(*x <= x1 + 1e-9, "swipe x overshot target: {x} > {x1}");
        prev = *x;
    }
}

#[test]
fn swipe_points_decelerate_ease_out() {
    // Ease-out: the first segment covers more ground than the last (a real flick
    // is fast then settles).
    let pts = swipe_points(0.0, 0.0, 250.0, 0.0, 25);
    let first_gap = pts[0].0 - 0.0;
    let last_gap = pts[24].0 - pts[23].0;
    assert!(
        first_gap > last_gap,
        "ease-out swipe should start faster than it ends: first {first_gap:.2} last {last_gap:.2}"
    );
}

#[test]
fn swipe_points_handles_zero_steps_without_panic() {
    let pts = swipe_points(0.0, 0.0, 100.0, 100.0, 0);
    // Clamped to one step that lands on the target.
    assert_eq!(pts.len(), 1);
    assert_eq!(pts[0], (100.0, 100.0));
}
