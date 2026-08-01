use super::*;

// Shared across both responsibility-split test submodules; lives in the root so
// each reaches it via `use super::*`.
const ALL_TEST_PROFILES: &[StealthProfile] = &[
    StealthProfile::ChromeWindowsStable,
    StealthProfile::ChromeWindowsLegacy96,
    StealthProfile::ChromeMacStable,
    StealthProfile::EdgeWindowsStable,
    StealthProfile::Ie11Windows,
    StealthProfile::FirefoxLinux,
    StealthProfile::FirefoxWindows,
    StealthProfile::ChromeAndroid,
    StealthProfile::SafariIphone,
    StealthProfile::SafariIpad,
    StealthProfile::SafariMacStable,
    StealthProfile::ChromeLinux,
    StealthProfile::BraveWindows,
    StealthProfile::OperaWindows,
    StealthProfile::SamsungInternetAndroid,
];

mod identity_and_emission;
mod js_and_facts;
