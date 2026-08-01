use super::*;
use crate::fingerprint::geo_coherence::{identity_geo_coherence, GeoCoherence};
use crate::fingerprint::identity::NavigatorProfile;

#[test]
fn built_in_regions_cover_shipped_timezones() {
    // Every timezone used by a shipped identity must have an exact GeoRegion entry
    // so persona generation is single-owner.
    for tz in [
        "America/New_York",
        "America/Chicago",
        "America/Los_Angeles",
        "Europe/London",
        "Europe/Berlin",
        "Asia/Tokyo",
    ] {
        assert!(
            geo_region_by_timezone(tz).is_some(),
            "no GeoRegion for shipped timezone {tz}"
        );
    }
}

#[test]
fn geo_region_by_timezone_falls_back_to_area() {
    // America/Denver is not a built-in preset, but it shares the America/ area.
    let region = geo_region_by_timezone("America/Denver").unwrap();
    assert!(region.timezone.starts_with("America/"));
    assert_eq!(region.country, "US");
}

#[test]
fn every_geo_region_is_internally_coherent() {
    for region in GEO_REGIONS {
        let id = NavigatorProfile {
            stealth_profile_name: String::new(),
            hardware_index: 0,
            user_agent: String::new(),
            platform: String::new(),
            vendor: String::new(),
            screen_width: 1920,
            screen_height: 1080,
            color_depth: 24,
            device_memory: 8,
            hardware_concurrency: 4,
            timezone: region.timezone.to_string(),
            locale: region.locale.to_string(),
            languages: region.languages.iter().map(|s| s.to_string()).collect(),
            latitude: region.lat,
            longitude: region.lon,
            webgl_vendor: String::new(),
            webgl_renderer: String::new(),
            canvas_seed: 0.0,
            do_not_track: None,
            country: region.country.to_string(),
        };
        assert_eq!(
            identity_geo_coherence(&id),
            GeoCoherence::Coherent,
            "built-in region {:?} is not coherent",
            region.name
        );
    }
}

#[test]
fn identities_derive_all_geo_surfaces_from_one_region() {
    // G127: the five geo-derived surfaces (timezone, locale, languages,
    // geolocation coordinates, proxy/WebRTC country) all come from the single
    // GeoRegion owner.
    for region in GEO_REGIONS {
        let id = NavigatorProfile {
            stealth_profile_name: String::new(),
            hardware_index: 0,
            user_agent: String::new(),
            platform: String::new(),
            vendor: String::new(),
            screen_width: 1920,
            screen_height: 1080,
            color_depth: 24,
            device_memory: 8,
            hardware_concurrency: 4,
            timezone: region.timezone.to_string(),
            locale: region.locale.to_string(),
            languages: region.languages.iter().map(|s| s.to_string()).collect(),
            latitude: region.lat,
            longitude: region.lon,
            webgl_vendor: String::new(),
            webgl_renderer: String::new(),
            canvas_seed: 0.0,
            do_not_track: None,
            country: region.country.to_string(),
        };
        assert_eq!(id.timezone, region.timezone);
        assert_eq!(id.locale, region.locale);
        assert_eq!(
            id.languages,
            region
                .languages
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(id.latitude, region.lat);
        assert_eq!(id.longitude, region.lon);
        assert_eq!(id.country, region.country);
        assert_eq!(identity_geo_coherence(&id), GeoCoherence::Coherent);
    }
}

#[cfg(feature = "tier-b-toml")]
#[test]
fn tier_b_geo_region_presets_are_coherent() {
    // G129/G130: ship region presets as Tier-B TOML and prove each one passes the
    // geo-coherence gate.
    let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tier_b/geo_regions"));
    if !dir.exists() {
        return; // directory may be absent in some test configurations
    }
    let regions = load_geo_region_directory(dir).expect("Tier-B geo-region load failed");
    assert!(!regions.is_empty(), "no Tier-B geo-region presets found");
    for region in &regions {
        let id = NavigatorProfile {
            stealth_profile_name: String::new(),
            hardware_index: 0,
            user_agent: String::new(),
            platform: String::new(),
            vendor: String::new(),
            screen_width: 1920,
            screen_height: 1080,
            color_depth: 24,
            device_memory: 8,
            hardware_concurrency: 4,
            timezone: region.timezone.to_string(),
            locale: region.locale.to_string(),
            languages: region.languages.iter().map(|s| s.to_string()).collect(),
            latitude: region.lat,
            longitude: region.lon,
            webgl_vendor: String::new(),
            webgl_renderer: String::new(),
            canvas_seed: 0.0,
            do_not_track: None,
            country: region.country.to_string(),
        };
        assert_eq!(
            identity_geo_coherence(&id),
            GeoCoherence::Coherent,
            "Tier-B region {:?} failed the geo-coherence gate",
            region.name
        );
    }
}

#[cfg(feature = "tier-b-toml")]
#[test]
fn tier_b_geo_region_loader_rejects_incoherent_preset() {
    let bad_toml = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/bad_geo_region.toml"
    );
    let result = load_geo_region_from_toml(std::path::Path::new(bad_toml));
    assert!(
        result.is_err(),
        "incoherent Tier-B geo-region must fail closed"
    );
}
