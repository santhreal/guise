//! Unit tests for persona rarity scoring (G104).

use super::*;

#[test]
fn chrome_windows_is_most_common() {
    let (most_common, score) = personas_by_rarity().next().expect("at least one persona");
    assert_eq!(most_common, StealthProfile::ChromeWindowsStable);
    assert_eq!(score, 100, "ChromeWindowsStable must be the modal persona");
}

#[test]
fn ie11_is_rarest() {
    let (rarest, score) = personas_by_rarity().last().expect("at least one persona");
    assert_eq!(rarest, StealthProfile::Ie11Windows);
    assert!(score <= 5, "IE11 must be the rarest persona");
}

#[test]
fn modal_threshold_is_met_by_major_desktop_browsers() {
    for profile in [
        StealthProfile::ChromeWindowsStable,
        StealthProfile::FirefoxLinux,
        StealthProfile::FirefoxWindows,
        StealthProfile::ChromeMacStable,
        StealthProfile::ChromeLinux,
        StealthProfile::SafariMacStable,
    ] {
        assert!(
            is_modal(profile),
            "{profile:?} is a major desktop persona and must be modal"
        );
    }
}

#[test]
fn niche_browsers_are_not_modal() {
    for profile in [
        StealthProfile::BraveWindows,
        StealthProfile::OperaWindows,
        StealthProfile::Ie11Windows,
        StealthProfile::ChromeWindowsLegacy96,
    ] {
        assert!(
            !is_modal(profile),
            "{profile:?} is a niche/legacy persona and must not be modal"
        );
    }
}

#[test]
fn all_profiles_have_a_non_zero_score() {
    for profile in guise_profiles::ALL_PROFILES {
        let score = rarity_score(*profile);
        assert!(
            score > 0 && score <= 100,
            "{profile:?} must have a rarity score in 1..=100, got {score}"
        );
    }
}

#[test]
fn personas_by_rarity_is_sorted_descending() {
    let scores: Vec<_> = personas_by_rarity().map(|(_, s)| s).collect();
    for window in scores.windows(2) {
        assert!(
            window[0] >= window[1],
            "rarity scores must be sorted descending: {:?}",
            window
        );
    }
}
