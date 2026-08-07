//! Coherent browser identity profiles.
//!
//! A browser identity combines a canonical fingerprint profile with geographic
//! and language facts. Anti-bot systems cross-check these surfaces: a Windows
//! user agent with a Linux platform, or a US timezone with a Japanese language
//! stack, is more suspicious than plain headless automation.

use serde::{Deserialize, Serialize};

use crate::choice::weighted_index_by_with_rng;
use crate::sampling::{seeded_rng, RngSeed};
use guise_profiles::{named_profile, profile_name, DEFAULT_STEALTH_PROFILE};

use super::geo_region::geo_region_by_timezone;
use super::{infer_profile_from_user_agent, profile_to_overrides_at, GeoRegion, StealthProfile, GEO_REGIONS};
use crate::fingerprint::rarity::rarity_score;

/// A coherent browser identity with browser, hardware, locale, and geo fields.
///
/// This is the single persona identity type: every layer (browser JS overrides,
/// HTTP headers, TLS ClientHello, geo coherence) can be derived from it via
/// [`Self::to_overrides`] and [`Self::to_bundle`]. Keeping the identity in one
/// place prevents the same persona from being reconstructed differently by
/// different subsystems.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NavigatorProfile {
    /// Canonical name of the stealth profile this identity is based on.
    ///
    /// Stored as a string so `NavigatorProfile` stays serializable without
    /// forcing a `serde` dependency onto `guise_profiles::StealthProfile`.
    pub stealth_profile_name: String,
    /// Index into the hardware-variant table for this profile.
    pub hardware_index: usize,
    /// Browser User-Agent string.
    pub user_agent: String,
    /// JavaScript-visible `navigator.platform` value.
    pub platform: String,
    /// JavaScript-visible `navigator.vendor` value.
    pub vendor: String,
    /// Screen width in CSS pixels.
    pub screen_width: u32,
    /// Screen height in CSS pixels.
    pub screen_height: u32,
    /// Screen color depth in bits.
    pub color_depth: u8,
    /// JavaScript-visible `navigator.deviceMemory` value in GiB.
    pub device_memory: u8,
    /// JavaScript-visible `navigator.hardwareConcurrency` value.
    pub hardware_concurrency: u8,
    /// IANA timezone identifier.
    pub timezone: String,
    /// Primary locale, for example `en-US`.
    pub locale: String,
    /// Ordered `navigator.languages` values.
    pub languages: Vec<String>,
    /// Latitude in decimal degrees.
    pub latitude: f64,
    /// Longitude in decimal degrees.
    pub longitude: f64,
    /// ISO-3166-1 alpha-2 country from the single-owner geo region; used for
    /// proxy-geo and WebRTC coherence.
    #[serde(default)]
    pub country: String,
    /// WebGL vendor string for `UNMASKED_VENDOR_WEBGL`.
    pub webgl_vendor: String,
    /// WebGL renderer string for `UNMASKED_RENDERER_WEBGL`.
    pub webgl_renderer: String,
    /// Canvas noise seed, deterministic per identity.
    pub canvas_seed: f64,
    /// Do Not Track header preference.
    pub do_not_track: Option<String>,
}

impl NavigatorProfile {
    fn stealth_profile(&self) -> StealthProfile {
        named_profile(&self.stealth_profile_name)
            .or_else(|| infer_profile_from_user_agent(&self.user_agent))
            .unwrap_or(DEFAULT_STEALTH_PROFILE)
    }

    /// Try resolving the canonical [`StealthProfile`] for this identity.
    ///
    /// Returns `Some(StealthProfile)` if the identity's profile name or User-Agent
    /// matches a known profile in the catalogue, or `None` if unrecognized.
    #[must_use]
    pub fn try_stealth_profile(&self) -> Option<StealthProfile> {
        named_profile(&self.stealth_profile_name)
            .or_else(|| infer_profile_from_user_agent(&self.user_agent))
    }

    /// Build the runtime browser overrides for this identity.
    ///
    /// This is the canonical path from the single identity type to the JS-injection
    /// and pref layers; any other code that needs a `ProfileOverrides` for this
    /// persona should call this method rather than reconstructing from fields.
    #[must_use]
    pub fn to_overrides(&self) -> super::profiles::ProfileOverrides {
        profile_to_overrides_at(&self.stealth_profile(), self.hardware_index)
    }

    /// Build the browser+TLS bundle for this identity.
    ///
    /// This is the canonical path from the single identity type to the network
    /// fingerprint layers; it guarantees the TLS family matches the browser family.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn to_bundle(&self) -> super::bundle::ProfileBundle {
        super::bundle::ProfileBundle::for_browser(self.stealth_profile())
    }

    /// This persona's INTERNAL geo-coherence, whether its [`timezone`](Self::timezone),
    /// [`locale`](Self::locale), primary [`languages`](Self::languages) entry, and
    /// coordinates mutually agree. Every shipped identity is coherent by contract
    /// (`every_shipped_identity_is_internally_geo_coherent`); this lets a caller
    /// re-check a mutated or externally-sourced identity. See
    /// [`crate::fingerprint::geo_coherence`].
    #[must_use]
    pub fn geo_coherence(&self) -> super::geo_coherence::GeoCoherence {
        super::geo_coherence::identity_geo_coherence(self)
    }

    /// Probe this persona's claimed geography against the operator-supplied egress
    /// geography (the country/timezone the proxy's IP geolocates to): the
    /// "timezone says New York, but the IP says Germany" tell. The operator
    /// supplies the egress facts, guise does not resolve IPs itself. See
    /// [`super::geo_coherence::persona_geo_self_probe`].
    #[must_use]
    pub fn egress_geo_self_probe(
        &self,
        observed: &super::geo_coherence::ObservedEgressGeo,
    ) -> super::geo_coherence::GeoSelfProbe {
        super::geo_coherence::persona_geo_self_probe(self, observed)
    }
}

#[derive(Debug, Clone, Copy)]
struct NavigatorProfileTemplate {
    stealth_profile: StealthProfile,
    hardware_index: usize,
    geo_region: &'static GeoRegion,
    canvas_seed: f64,
    do_not_track: Option<&'static str>,
}

impl NavigatorProfileTemplate {
    fn materialize(self) -> NavigatorProfile {
        let overrides = profile_to_overrides_at(&self.stealth_profile, self.hardware_index);

        NavigatorProfile {
            stealth_profile_name: profile_name(self.stealth_profile).to_string(),
            hardware_index: self.hardware_index,
            user_agent: overrides.user_agent,
            platform: overrides.platform,
            vendor: overrides.navigator_vendor,
            screen_width: overrides.screen_width,
            screen_height: overrides.screen_height,
            color_depth: overrides.color_depth,
            device_memory: overrides.device_memory as u8,
            hardware_concurrency: overrides.hardware_concurrency as u8,
            timezone: self.geo_region.timezone.to_string(),
            locale: self.geo_region.locale.to_string(),
            languages: self
                .geo_region
                .languages
                .iter()
                .map(|language| (*language).to_string())
                .collect(),
            latitude: self.geo_region.lat,
            longitude: self.geo_region.lon,
            country: self.geo_region.country.to_string(),
            webgl_vendor: overrides.webgl_vendor,
            webgl_renderer: overrides.webgl_renderer,
            canvas_seed: self.canvas_seed,
            do_not_track: self.do_not_track.map(str::to_string),
        }
    }
}

const PROFILES: &[NavigatorProfileTemplate] = &[
    NavigatorProfileTemplate {
        stealth_profile: StealthProfile::ChromeWindowsStable,
        hardware_index: 1,
        geo_region: &GEO_REGIONS[0], // US East
        canvas_seed: 0.3847,
        do_not_track: None,
    },
    NavigatorProfileTemplate {
        stealth_profile: StealthProfile::ChromeWindowsStable,
        hardware_index: 2,
        geo_region: &GEO_REGIONS[2], // US West
        canvas_seed: -0.6291,
        do_not_track: None,
    },
    NavigatorProfileTemplate {
        stealth_profile: StealthProfile::ChromeWindowsStable,
        hardware_index: 3,
        geo_region: &GEO_REGIONS[4], // EU UK
        canvas_seed: 0.1523,
        do_not_track: Some("1"),
    },
    NavigatorProfileTemplate {
        stealth_profile: StealthProfile::ChromeMacStable,
        hardware_index: 0,
        geo_region: &GEO_REGIONS[1], // US Central
        canvas_seed: -0.4102,
        do_not_track: None,
    },
    NavigatorProfileTemplate {
        stealth_profile: StealthProfile::ChromeLinux,
        hardware_index: 1,
        geo_region: &GEO_REGIONS[3], // EU Germany
        canvas_seed: 0.7834,
        do_not_track: Some("1"),
    },
    NavigatorProfileTemplate {
        stealth_profile: StealthProfile::ChromeWindowsStable,
        hardware_index: 4,
        geo_region: &GEO_REGIONS[6], // APAC Japan
        canvas_seed: -0.2519,
        do_not_track: None,
    },
];

/// Get a random coherent identity profile.
pub fn random() -> NavigatorProfile {
    crate::choice::random_item(PROFILES)
        .unwrap_or(&PROFILES[0])
        .materialize()
}

/// Get an identity matching a timezone, falling back by region then random.
pub fn for_timezone(tz: &str) -> NavigatorProfile {
    if let Some(region) = geo_region_by_timezone(tz) {
        for profile in PROFILES {
            if profile.geo_region.timezone == region.timezone {
                return profile.materialize();
            }
        }
    }
    random()
}

/// Get an identity by index, wrapping around the built-in profile count.
pub fn by_index(idx: usize) -> NavigatorProfile {
    PROFILES[idx % PROFILES.len()].materialize()
}

/// Return the number of built-in identity profiles.
pub fn profile_count() -> usize {
    PROFILES.len()
}

/// Build a deterministic identity from a single seed.
///
/// G225/G226: the same seed always produces the same identity, so persona
/// selection, behavioral sampling, and fingerprint derivation can all be rooted
/// in one reproducible value.
#[must_use]
pub fn seeded(seed: &RngSeed) -> NavigatorProfile {
    let mut rng = seeded_rng(&seed.bytes);
    let index = crate::choice::random_index_with_rng(PROFILES.len(), &mut rng).unwrap_or(0);
    PROFILES[index].materialize()
}

/// Build a deterministic identity with persona selection biased toward modal,
/// common personas.
///
/// G231/G232: weights come from [`rarity_score`], so Chrome/Windows and the
/// large Firefox buckets are chosen more often than niche Brave/Opera/IE11
/// personas while every shipped profile still has a non-zero chance.
#[must_use]
pub fn seeded_weighted(seed: &RngSeed) -> NavigatorProfile {
    let mut rng = seeded_rng(&seed.bytes);
    let index = weighted_index_by_with_rng(
        PROFILES,
        |t| rarity_score(t.stealth_profile) as f64,
        &mut rng,
    )
    .unwrap_or(0);
    PROFILES[index].materialize()
}

#[cfg(test)]
mod tests {
    use super::super::{profile_hardware_at, profile_to_overrides};
    use super::*;

    #[test]
    fn all_profiles_materialize() {
        for (i, profile) in PROFILES.iter().enumerate() {
            let id = profile.materialize();
            assert!(!id.user_agent.is_empty(), "profile {i} has empty UA");
            assert!(!id.platform.is_empty(), "profile {i} has empty platform");
            assert!(!id.timezone.is_empty(), "profile {i} has empty timezone");
            assert!(id.screen_width > 0, "profile {i} has empty width");
            assert!(id.screen_height > 0, "profile {i} has empty height");
        }
    }

    #[test]
    fn identity_user_agents_delegate_to_stealth_profiles() {
        for profile in PROFILES {
            let id = profile.materialize();
            let overrides = profile_to_overrides(&profile.stealth_profile);
            let hardware = profile_hardware_at(profile.stealth_profile, profile.hardware_index);

            assert_eq!(
                id.user_agent, overrides.user_agent,
                "identity UA drifted from stealth profile {:?}",
                profile.stealth_profile,
            );
            assert_eq!(
                id.platform, overrides.platform,
                "identity platform drifted from stealth profile {:?}",
                profile.stealth_profile,
            );
            assert_eq!(
                id.vendor, overrides.navigator_vendor,
                "identity navigator vendor drifted from stealth profile {:?}",
                profile.stealth_profile,
            );
            assert_eq!(id.screen_width, hardware.screen_width);
            assert_eq!(id.screen_height, hardware.screen_height);
            assert_eq!(id.color_depth, hardware.color_depth);
            assert_eq!(id.device_memory, hardware.device_memory);
            assert_eq!(id.hardware_concurrency, hardware.hardware_concurrency);
            assert_eq!(id.webgl_vendor, hardware.webgl_vendor);
            assert_eq!(id.webgl_renderer, hardware.webgl_renderer);
            assert!(!id.user_agent.contains("Chrome/130."));
        }
    }

    #[test]
    fn random_returns_valid() {
        let id = random();
        assert!(id.user_agent.contains("Chrome"));
        assert!(id.screen_width >= 1024);
    }

    #[test]
    fn for_timezone_us_east() {
        let id = for_timezone("America/New_York");
        assert_eq!(id.timezone, "America/New_York");
    }

    #[test]
    fn for_timezone_fallback() {
        let id = for_timezone("Africa/Lagos");
        assert!(!id.user_agent.is_empty());
    }

    #[test]
    fn profiles_internally_consistent() {
        for profile in PROFILES {
            let id = profile.materialize();
            if id.platform == "Win32" {
                assert!(
                    id.user_agent.contains("Windows"),
                    "Win32 platform but no Windows UA"
                );
            }
            if id.platform == "MacIntel" {
                assert!(
                    id.user_agent.contains("Macintosh"),
                    "MacIntel platform but no Mac UA"
                );
            }
            if id.platform == "Linux x86_64" {
                assert!(
                    id.user_agent.contains("Linux"),
                    "Linux platform but no Linux UA"
                );
            }
            assert!(!id.languages.is_empty(), "empty languages");
        }
    }

    #[test]
    fn by_index_deterministic() {
        let a = by_index(0);
        let b = by_index(0);
        assert_eq!(a.user_agent, b.user_agent);
    }

    #[test]
    fn profile_count_matches() {
        assert_eq!(profile_count(), PROFILES.len());
    }

    #[test]
    fn navigator_profile_geo_coherence_method_agrees_with_the_free_function() {
        use crate::fingerprint::geo_coherence::{identity_geo_coherence, GeoCoherence};
        let id = by_index(0);
        assert_eq!(id.geo_coherence(), identity_geo_coherence(&id));
        assert_eq!(id.geo_coherence(), GeoCoherence::Coherent);
    }

    #[test]
    fn for_timezone_and_random_return_geo_coherent_identities() {
        use crate::fingerprint::geo_coherence::GeoCoherence;
        // The locale-aware selector must never hand back an incoherent persona.
        for tz in [
            "America/New_York",
            "Europe/Berlin",
            "Asia/Tokyo",
            "Europe/London",
        ] {
            let id = for_timezone(tz);
            assert_eq!(
                id.geo_coherence(),
                GeoCoherence::Coherent,
                "for_timezone({tz}) returned a geo-incoherent identity ({}/{}) ",
                id.timezone,
                id.locale
            );
        }
        for _ in 0..20 {
            assert_eq!(random().geo_coherence(), GeoCoherence::Coherent);
        }
    }

    #[test]
    fn egress_self_probe_method_flags_a_mismatched_proxy_country() {
        use crate::fingerprint::geo_coherence::{
            EgressGeoMismatch, GeoSelfProbe, ObservedEgressGeo,
        };
        let id = by_index(0); // America/New_York → US
        let observed = ObservedEgressGeo {
            country: Some("DE".to_string()),
            timezone: None,
        };
        match id.egress_geo_self_probe(&observed) {
            GeoSelfProbe::Incoherent(ms) => assert_eq!(
                ms[0],
                EgressGeoMismatch::Country {
                    persona_country: "US".to_string(),
                    egress_country: "DE".to_string(),
                }
            ),
            other => panic!("expected a country mismatch, got {other:?}"),
        }
    }

    #[test]
    fn identity_to_overrides_matches_profile_to_overrides_at() {
        // G082: NavigatorProfile is the single source; the overrides derived from
        // it must be identical to the canonical profile_to_overrides_at path.
        for profile in PROFILES {
            let id = profile.materialize();
            let from_identity = id.to_overrides();
            let from_profile = profile_to_overrides_at(&id.stealth_profile(), id.hardware_index);
            assert_eq!(from_identity, from_profile);
        }
    }

    #[test]
    fn identity_carries_its_source_profile_and_hardware_index() {
        for profile in PROFILES {
            let id = profile.materialize();
            assert_eq!(
                id.stealth_profile_name,
                profile_name(profile.stealth_profile)
            );
            assert_eq!(id.hardware_index, profile.hardware_index);
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn identity_to_bundle_is_fully_coherent() {
        // G082: the identity-derived bundle must pass the same full coherence gate
        // that a bundle built directly from StealthProfile passes.
        for profile in PROFILES {
            let id = profile.materialize();
            let bundle = id.to_bundle();
            assert_eq!(bundle.browser, id.stealth_profile());
            bundle
                .validate_full_coherence()
                .expect("identity-derived bundle must be fully coherent");
        }
    }

    #[test]
    fn seeded_identity_is_deterministic() {
        let seed = RngSeed::from_u64(0xC0FFEE);
        let a = seeded(&seed);
        let b = seeded(&seed);
        assert_eq!(a, b);
    }

    #[test]
    fn seeded_identity_differs_across_seeds() {
        // The same template can be chosen by chance; verify that at least one of
        // several distinct seeds produces a different identity than the others.
        let baseline = seeded(&RngSeed::from_u64(1));
        let mut any_different = false;
        for seed in 2..20 {
            if seeded(&RngSeed::from_u64(seed)) != baseline {
                any_different = true;
                break;
            }
        }
        assert!(
            any_different,
            "different seeds should produce different personas"
        );
    }

    #[test]
    fn seeded_weighted_identity_is_deterministic() {
        let seed = RngSeed::from_u64(0xDECAF);
        let a = seeded_weighted(&seed);
        let b = seeded_weighted(&seed);
        assert_eq!(a, b);
    }

    #[test]
    fn seeded_weighted_prefers_modal_profiles() {
        let mut counts = std::collections::HashMap::<String, usize>::new();
        for seed in 0..10_000 {
            let id = seeded_weighted(&RngSeed::from_u64(seed));
            let name = profile_name(id.stealth_profile()).to_string();
            *counts.entry(name).or_insert(0) += 1;
        }

        let modal_name = profile_name(StealthProfile::ChromeWindowsStable);
        let rare_name = profile_name(StealthProfile::Ie11Windows);
        let modal_count = counts.get(modal_name).copied().unwrap_or(0);
        let rare_count = counts.get(rare_name).copied().unwrap_or(0);
        assert!(
            modal_count > rare_count * 10,
            "modal ChromeWindows should be chosen far more often than IE11: {modal_count} vs {rare_count}"
        );
        // Every unique profile that appears in the built-in templates is observed
        // at least once across 10k weighted draws.
        let expected: std::collections::HashSet<String> = PROFILES
            .iter()
            .map(|t| profile_name(t.stealth_profile).to_string())
            .collect();
        for name in expected {
            assert!(
                counts.contains_key(&name),
                "weighted selection never chose profile {name} in 10k draws"
            );
        }
    }

    #[test]
    fn seeded_identity_is_geo_coherent() {
        let id = seeded(&RngSeed::from_u64(0xBEEF));
        assert_eq!(
            id.geo_coherence(),
            crate::fingerprint::geo_coherence::GeoCoherence::Coherent
        );
    }

    #[test]
    fn unrecognized_profile_name_infers_from_user_agent() {
        let mut id = seeded(&RngSeed::from_u64(42));
        // Corrupt stealth_profile_name to an unknown value while keeping a Firefox Linux UA.
        id.stealth_profile_name = "corrupted-profile-name".to_string();
        id.user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0".to_string();

        assert_eq!(
            id.stealth_profile(),
            StealthProfile::FirefoxLinux,
            "unrecognized profile_name should infer FirefoxLinux from user_agent, not default to Chrome"
        );
        assert_eq!(
            id.try_stealth_profile(),
            Some(StealthProfile::FirefoxLinux)
        );

        // Completely invalid UA and name
        id.user_agent = "UnknownBot/1.0".to_string();
        assert_eq!(id.try_stealth_profile(), None);
    }
}
