//! Unit tests for the Tier-B screen / DPR persona library loader (G097).

use super::*;

/// Path to the shipped Tier-B screen library, relative to the workspace root.
fn shipped_screen_dir() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("tier_b").join("screen")
}

#[test]
fn shipped_screen_library_loads_all_files() {
    let screens = load_screen_directory(&shipped_screen_dir()).expect("shipped library must load");
    assert!(
        screens.len() >= 10,
        "expected at least 10 screen personas, got {}",
        screens.len()
    );

    let has_desktop = screens.iter().any(|s| s.width == 1920 && s.height == 1080);
    assert!(has_desktop, "library must include 1920x1080 desktop");

    let has_macbook = screens.iter().any(|s| s.width == 1728 && s.height == 1117);
    assert!(has_macbook, "library must include MacBook 1728x1117");

    let has_iphone = screens.iter().any(|s| s.width == 390 && s.height == 844);
    assert!(has_iphone, "library must include iPhone 390x844");

    let has_ipad = screens.iter().any(|s| s.width == 1024 && s.height == 1366);
    assert!(has_ipad, "library must include iPad 1024x1366");
}

#[test]
fn every_shipped_profile_screen_exists_in_tier_b_library() {
    // G097 contract: every non-passthrough built-in screen size must be reachable
    // in the Tier-B library. Mobile/tablet DPRs are not currently wired, so we
    // match only width x height x color_depth here.
    let screens = load_screen_directory(&shipped_screen_dir()).expect("shipped library must load");
    let set: std::collections::HashSet<_> = screens
        .iter()
        .map(|s| (s.width, s.height, s.color_depth))
        .collect();

    for profile in guise_profiles::ALL_PROFILES {
        let facts = guise_profiles::profile_facts(*profile);
        let hw = guise_profiles::profile_hardware(*profile);
        assert!(
            set.contains(&(facts.screen_width, facts.screen_height, hw.color_depth)),
            "{profile:?} screen ({}x{}, depth {}) must be in the Tier-B library",
            facts.screen_width,
            facts.screen_height,
            hw.color_depth
        );
    }
}

#[test]
fn screen_persona_physical_pixels_match_dpr() {
    let s = ScreenPersona {
        width: 390,
        height: 844,
        dpr: 3.0,
        color_depth: 24,
    };
    assert_eq!(s.physical_width(), 1170);
    assert_eq!(s.physical_height(), 2532);
}

#[test]
fn mobile_viewport_classification() {
    let mobile = ScreenPersona {
        width: 390,
        height: 844,
        dpr: 3.0,
        color_depth: 24,
    };
    assert!(mobile.is_mobile());

    let desktop = ScreenPersona {
        width: 1920,
        height: 1080,
        dpr: 1.0,
        color_depth: 24,
    };
    assert!(!desktop.is_mobile());
}

#[test]
fn zero_width_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-screen-zero-width-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.toml");
    std::fs::write(
        &path,
        "[[screen]]\nwidth = 0\nheight = 1080\ndpr = 1.0\ncolor_depth = 24\n",
    )
    .unwrap();

    let err = load_screens_from_toml(&path).expect_err("zero width must be rejected");
    assert!(
        format!("{err}").contains("width must be > 0"),
        "expected zero-width error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zero_dpr_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-screen-zero-dpr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.toml");
    std::fs::write(
        &path,
        "[[screen]]\nwidth = 1920\nheight = 1080\ndpr = 0.0\ncolor_depth = 24\n",
    )
    .unwrap();

    let err = load_screens_from_toml(&path).expect_err("zero dpr must be rejected");
    assert!(
        format!("{err}").contains("dpr must be a positive finite number"),
        "expected zero-dpr error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_color_depth_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-screen-bad-depth-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.toml");
    std::fs::write(
        &path,
        "[[screen]]\nwidth = 1920\nheight = 1080\ndpr = 1.0\ncolor_depth = 42\n",
    )
    .unwrap();

    let err = load_screens_from_toml(&path).expect_err("invalid color depth must be rejected");
    assert!(
        format!("{err}").contains("not a realistic display depth"),
        "expected color-depth error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oversized_file_is_rejected() {
    let dir = std::env::temp_dir().join(format!("guise-screen-oversize-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("huge.toml");
    let payload = format!(
        "# {}\n[[screen]]\nwidth = 1\nheight = 1\ndpr = 1.0\ncolor_depth = 24\n",
        "x".repeat(65 * 1024)
    );
    std::fs::write(&path, payload).unwrap();

    let err = load_screens_from_toml(&path).expect_err("oversize file must be rejected");
    assert!(
        format!("{err}").contains("over the 65536-byte cap"),
        "expected oversize error, got {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
