use super::*;
use crate::fingerprint::identity;

/// Build a coherent baseline persona (the US-East identity) to mutate per case.
fn baseline() -> NavigatorProfile {
    let id = identity::by_index(0);
    assert_eq!(id.timezone, "America/New_York", "baseline identity drifted");
    id
}

// ── Reference-table integrity ───────────────────────────────────────────────

#[test]
fn timezone_facts_table_is_well_formed() {
    let mut seen = std::collections::HashSet::new();
    for f in TIMEZONE_FACTS {
        assert!(
            seen.insert(f.timezone),
            "duplicate timezone key {}",
            f.timezone
        );
        assert!(
            f.timezone.contains('/'),
            "{} is not an IANA Area/Location id",
            f.timezone
        );
        assert_eq!(f.country.len(), 2, "{} country must be ISO-2", f.timezone);
        assert!(
            f.country.chars().all(|c| c.is_ascii_uppercase()),
            "{} country must be uppercase",
            f.timezone
        );
        assert!(!f.languages.is_empty(), "{} has no languages", f.timezone);
        for l in f.languages {
            assert!(
                !l.is_empty() && l.chars().all(|c| c.is_ascii_lowercase()),
                "{} language {l:?} must be a lowercase subtag",
                f.timezone
            );
        }
        assert!(
            (-90.0..=90.0).contains(&f.lat),
            "{} lat out of range",
            f.timezone
        );
        assert!(
            (-180.0..=180.0).contains(&f.lon),
            "{} lon out of range",
            f.timezone
        );
    }
}

#[test]
fn timezone_facts_lookup_hits_and_misses() {
    assert_eq!(timezone_facts("Asia/Tokyo").unwrap().country, "JP");
    assert_eq!(timezone_facts("America/New_York").unwrap().country, "US");
    assert!(timezone_facts("Africa/Lagos").is_none());
    assert!(timezone_facts("").is_none());
}

// ── The enforced invariant: every shipped persona is internally geo-coherent ──

#[test]
fn every_shipped_identity_is_internally_geo_coherent() {
    // This is the contract the `identity` module's doc only CLAIMED ("never a US
    // timezone with a Japanese language"), now ENFORCED: every persona's
    // timezone, locale, primary language, and coordinates must agree.
    for i in 0..identity::profile_count() {
        let id = identity::by_index(i);
        assert_eq!(
            identity_geo_coherence(&id),
            GeoCoherence::Coherent,
            "shipped identity {i} ({}, locale {}, langs {:?}) is geo-INCOHERENT",
            id.timezone,
            id.locale,
            id.languages
        );
    }
}

#[test]
fn every_shipped_identity_timezone_is_in_the_reference_catalogue() {
    // No shipped persona may resolve to `Unknown`: the built-in table must cover
    // every timezone the identity catalogue ships, or the self-probe goes dark for
    // it (silent coverage hole).
    for i in 0..identity::profile_count() {
        let id = identity::by_index(i);
        assert!(
            timezone_facts(&id.timezone).is_some(),
            "shipped identity timezone {} is not in TIMEZONE_FACTS",
            id.timezone
        );
    }
}

// ── Internal-coherence negative twins ───────────────────────────────────────

#[test]
fn locale_country_mismatch_is_incoherent() {
    let mut id = baseline();
    id.locale = "de-DE".to_string(); // German locale under a New York timezone
    match identity_geo_coherence(&id) {
        GeoCoherence::Incoherent(problems) => assert!(
            problems.iter().any(|p| matches!(
                p,
                GeoIncoherence::LocaleCountry { timezone_country, locale_region }
                    if timezone_country == "US" && locale_region == "DE"
            )),
            "expected a US-vs-DE LocaleCountry mismatch, got {problems:?}"
        ),
        other => panic!("expected Incoherent, got {other:?}"),
    }
}

#[test]
fn primary_language_mismatch_is_incoherent() {
    let mut id = baseline();
    id.languages = vec!["ja".to_string(), "en".to_string()]; // Japanese-first under NY
    match identity_geo_coherence(&id) {
        GeoCoherence::Incoherent(problems) => assert!(
            problems.iter().any(|p| matches!(
                p,
                GeoIncoherence::Language { primary_language, .. } if primary_language == "ja"
            )),
            "expected a Japanese-language mismatch, got {problems:?}"
        ),
        other => panic!("expected Incoherent, got {other:?}"),
    }
}

#[test]
fn implausible_coordinates_are_incoherent() {
    let mut id = baseline();
    id.latitude = 35.6762; // Tokyo coordinates under a New York timezone
    id.longitude = 139.6503;
    match identity_geo_coherence(&id) {
        GeoCoherence::Incoherent(problems) => {
            let coord = problems.iter().find_map(|p| match p {
                GeoIncoherence::Coordinates {
                    distance_km,
                    timezone,
                } => Some((*distance_km, timezone.clone())),
                _ => None,
            });
            let (distance, tz) = coord.expect("expected a Coordinates mismatch");
            assert_eq!(tz, "America/New_York");
            assert!(
                distance > 9000.0,
                "NY↔Tokyo should be ~10800 km, got {distance}"
            );
        }
        other => panic!("expected Incoherent, got {other:?}"),
    }
}

#[test]
fn within_zone_metro_coordinates_stay_coherent() {
    // San Francisco coordinates under America/Los_Angeles (~560 km from the LA
    // zone's representative point) must NOT trip the coarse coordinate guard.
    let mut id = baseline();
    id.timezone = "America/Los_Angeles".to_string();
    id.latitude = 34.0522; // downtown LA, far enough from the SF reference point
    id.longitude = -118.2437;
    assert_eq!(identity_geo_coherence(&id), GeoCoherence::Coherent);
}

#[test]
fn unknown_timezone_is_loud_not_a_silent_pass() {
    let mut id = baseline();
    id.timezone = "Africa/Lagos".to_string();
    match identity_geo_coherence(&id) {
        GeoCoherence::Unknown { timezone } => assert_eq!(timezone, "Africa/Lagos"),
        other => panic!("expected Unknown for an uncatalogued zone, got {other:?}"),
    }
    // And it is explicitly NOT coherent.
    assert!(!identity_geo_coherence(&id).is_coherent());
}

// ── Egress self-probe (the R056/R057 answer) ────────────────────────────────

#[test]
fn egress_self_probe_unmeasured_on_empty_observation() {
    let id = baseline();
    assert_eq!(
        persona_geo_self_probe(&id, &ObservedEgressGeo::default()),
        GeoSelfProbe::Unmeasured
    );
    assert!(ObservedEgressGeo::default().is_empty());
}

#[test]
fn egress_self_probe_coherent_when_country_matches() {
    let id = baseline(); // America/New_York → US
    let obs = ObservedEgressGeo {
        country: Some("US".to_string()),
        timezone: None,
    };
    assert_eq!(persona_geo_self_probe(&id, &obs), GeoSelfProbe::Coherent);
}

#[test]
fn egress_self_probe_country_is_case_insensitive() {
    let id = baseline();
    let obs = ObservedEgressGeo {
        country: Some("us".to_string()),
        timezone: None,
    };
    assert_eq!(persona_geo_self_probe(&id, &obs), GeoSelfProbe::Coherent);
}

#[test]
fn egress_self_probe_flags_country_mismatch() {
    // THE R056/R057 TELL: a New-York-timezone persona egressing from Germany.
    let id = baseline();
    let obs = ObservedEgressGeo {
        country: Some("DE".to_string()),
        timezone: None,
    };
    match persona_geo_self_probe(&id, &obs) {
        GeoSelfProbe::Incoherent(ms) => {
            assert_eq!(ms.len(), 1);
            assert_eq!(
                ms[0],
                EgressGeoMismatch::Country {
                    persona_country: "US".to_string(),
                    egress_country: "DE".to_string(),
                }
            );
        }
        other => panic!("expected Incoherent Country, got {other:?}"),
    }
}

#[test]
fn egress_self_probe_flags_timezone_mismatch() {
    let id = baseline(); // America/New_York
    let obs = ObservedEgressGeo {
        country: None,
        timezone: Some("Europe/Berlin".to_string()),
    };
    match persona_geo_self_probe(&id, &obs) {
        GeoSelfProbe::Incoherent(ms) => assert_eq!(
            ms[0],
            EgressGeoMismatch::Timezone {
                persona_timezone: "America/New_York".to_string(),
                egress_timezone: "Europe/Berlin".to_string(),
            }
        ),
        other => panic!("expected Incoherent Timezone, got {other:?}"),
    }
}

#[test]
fn egress_self_probe_reports_both_layers_when_both_disagree() {
    let id = baseline();
    let obs = ObservedEgressGeo {
        country: Some("DE".to_string()),
        timezone: Some("Europe/Berlin".to_string()),
    };
    match persona_geo_self_probe(&id, &obs) {
        GeoSelfProbe::Incoherent(ms) => {
            assert_eq!(ms.len(), 2, "both country and timezone must be flagged");
            assert!(ms
                .iter()
                .any(|m| matches!(m, EgressGeoMismatch::Country { .. })));
            assert!(ms
                .iter()
                .any(|m| matches!(m, EgressGeoMismatch::Timezone { .. })));
        }
        other => panic!("expected Incoherent with two mismatches, got {other:?}"),
    }
}

#[test]
fn egress_self_probe_coherent_when_both_layers_agree() {
    let id = baseline();
    let obs = ObservedEgressGeo {
        country: Some("US".to_string()),
        timezone: Some("America/New_York".to_string()),
    };
    assert_eq!(persona_geo_self_probe(&id, &obs), GeoSelfProbe::Coherent);
}

#[test]
fn egress_self_probe_unknown_persona_zone_does_not_falsely_pass_country() {
    // If the persona's timezone is uncatalogued, the country layer CANNOT be
    // compared (we don't know the persona's country), it must be SKIPPED, never
    // read as agreement. With only a country observation, that leaves nothing
    // compared → Unmeasured (Law 10: an unmeasurable layer is not a pass).
    let mut id = baseline();
    id.timezone = "Africa/Lagos".to_string();
    id.country = String::new(); // simulate an identity without an explicit region country
    let obs = ObservedEgressGeo {
        country: Some("US".to_string()),
        timezone: None,
    };
    assert_eq!(persona_geo_self_probe(&id, &obs), GeoSelfProbe::Unmeasured);
}

#[test]
fn egress_self_probe_timezone_layer_works_without_catalogue() {
    // The timezone layer is an exact string compare, so it works even for an
    // uncatalogued persona zone (no country resolution needed).
    let mut id = baseline();
    id.timezone = "Africa/Lagos".to_string();
    let obs = ObservedEgressGeo {
        country: None,
        timezone: Some("America/New_York".to_string()),
    };
    match persona_geo_self_probe(&id, &obs) {
        GeoSelfProbe::Incoherent(ms) => assert_eq!(
            ms[0],
            EgressGeoMismatch::Timezone {
                persona_timezone: "Africa/Lagos".to_string(),
                egress_timezone: "America/New_York".to_string(),
            }
        ),
        other => panic!("expected Incoherent Timezone, got {other:?}"),
    }
}
