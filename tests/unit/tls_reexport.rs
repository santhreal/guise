//! Verify scanclient TLS profiles are reachable through `guise::http`.
//!
//! Gated via `required-features = ["http"]` in Cargo.toml (the scanclient TLS
//! re-export lives behind the full `http` feature).

use guise::http::{supported_profiles, ImpersonateProfile, ParseProfileError};

#[test]
fn impersonate_profile_parse_roundtrip() {
    let p = ImpersonateProfile::parse("chrome131").unwrap();
    assert_eq!(p, ImpersonateProfile::Chrome131);
    assert_eq!(p.name(), "chrome131");
}

#[test]
fn supported_profiles_non_empty() {
    assert!(!supported_profiles().is_empty());
}

#[test]
fn parse_error_lists_supported() {
    let err = ImpersonateProfile::parse("not-a-browser").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not-a-browser"));
    let _ = ParseProfileError("x".into());
}
