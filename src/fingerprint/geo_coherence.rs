//! Persona geo-coherence (R056/R057): does a persona's **timezone**, **locale**,
//! and **coordinates** agree with each other, and with the country it actually
//! **egresses** from?
//!
//! Anti-bot systems cross-check these surfaces. A persona whose JS-visible
//! `Intl…timeZone` is `America/New_York` but whose `navigator.languages` is
//! `ja-JP`, or one whose timezone says New York while its egress IP geolocates to
//! Frankfurt, is a louder tell than plain automation. The [`identity`](super::identity)
//! module already PAIRS a timezone with a locale and coordinates per persona, but
//! nothing enforced that they cohere, and there was no check at all against the
//! egress IP's geography, the exact gap the CreepJS `America/Phoenix` + WebRTC
//! real-IP-leak sample surfaced.
//!
//! This module is a SCREWDRIVER, not a geolocator: it does NOT ship a GeoIP
//! database or resolve an IP to a country itself. The egress country/timezone is
//! an INPUT the operator (who owns the proxy) supplies; guise only reports whether
//! the persona it is emitting is coherent with that egress. It reports, it never
//! claims a target is exploitable.
//!
//! Like the Layer-2 wire self-probe ([`crate::http::session_coherence::persona_wire_self_probe`]),
//! an absent observation is never read as agreement: a `None` egress field is not
//! cross-checked, and an unknown timezone yields [`GeoCoherence::Unknown`] (loud),
//! never a silent pass (Law 10).

use super::identity::NavigatorProfile;

/// Reference facts for an IANA timezone: the ISO-3166-alpha-2 country it belongs
/// to, the primary language subtags spoken there (lowercased, e.g. `"en"`), and a
/// representative coordinate (a major city in the zone) used for a coarse
/// coordinates-plausibility check.
///
/// This is the always-available built-in default. It is intentionally a *data
/// table*, not behaviour, so a Tier-B TOML drop-in can extend it with more zones
/// without recompiling (the same contract the OS-network stacks and TLS targets
/// use); the columns here are the schema that loader must satisfy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TimezoneFacts {
    /// IANA timezone identifier, e.g. `"America/New_York"`.
    pub timezone: &'static str,
    /// ISO-3166-1 alpha-2 country code, uppercase, e.g. `"US"`.
    pub country: &'static str,
    /// Primary language subtags spoken in this zone, lowercased and ordered by
    /// prevalence, e.g. `["de", "en"]`. A persona's primary language must be one
    /// of these to be coherent with the zone.
    pub languages: &'static [&'static str],
    /// Representative latitude (a major city in the zone), decimal degrees.
    pub lat: f64,
    /// Representative longitude (a major city in the zone), decimal degrees.
    pub lon: f64,
}

/// Built-in timezone→geo reference. Covers every zone the shipped
/// [`identity`](super::identity) personas use plus a spread of common zones so the
/// self-probe is useful out of the box; a Tier-B file extends it.
pub const TIMEZONE_FACTS: &[TimezoneFacts] = &[
    // ── United States (the zones the identity catalogue + host TZ use) ──
    TimezoneFacts {
        timezone: "America/New_York",
        country: "US",
        languages: &["en"],
        lat: 40.7128,
        lon: -74.0060,
    },
    TimezoneFacts {
        timezone: "America/Chicago",
        country: "US",
        languages: &["en"],
        lat: 41.8781,
        lon: -87.6298,
    },
    TimezoneFacts {
        timezone: "America/Denver",
        country: "US",
        languages: &["en"],
        lat: 39.7392,
        lon: -104.9903,
    },
    TimezoneFacts {
        timezone: "America/Phoenix",
        country: "US",
        languages: &["en"],
        lat: 33.4484,
        lon: -112.0740,
    },
    TimezoneFacts {
        timezone: "America/Los_Angeles",
        country: "US",
        languages: &["en"],
        lat: 37.7749,
        lon: -122.4194,
    },
    // ── Europe ──
    TimezoneFacts {
        timezone: "Europe/London",
        country: "GB",
        languages: &["en"],
        lat: 51.5074,
        lon: -0.1278,
    },
    TimezoneFacts {
        timezone: "Europe/Berlin",
        country: "DE",
        languages: &["de", "en"],
        lat: 52.5200,
        lon: 13.4050,
    },
    TimezoneFacts {
        timezone: "Europe/Paris",
        country: "FR",
        languages: &["fr"],
        lat: 48.8566,
        lon: 2.3522,
    },
    TimezoneFacts {
        timezone: "Europe/Madrid",
        country: "ES",
        languages: &["es"],
        lat: 40.4168,
        lon: -3.7038,
    },
    TimezoneFacts {
        timezone: "Europe/Amsterdam",
        country: "NL",
        languages: &["nl", "en"],
        lat: 52.3676,
        lon: 4.9041,
    },
    // ── Asia / Pacific / Americas ──
    TimezoneFacts {
        timezone: "Asia/Tokyo",
        country: "JP",
        languages: &["ja"],
        lat: 35.6762,
        lon: 139.6503,
    },
    TimezoneFacts {
        timezone: "Asia/Shanghai",
        country: "CN",
        languages: &["zh"],
        lat: 31.2304,
        lon: 121.4737,
    },
    TimezoneFacts {
        timezone: "Asia/Kolkata",
        country: "IN",
        languages: &["en", "hi"],
        lat: 28.6139,
        lon: 77.2090,
    },
    TimezoneFacts {
        timezone: "Australia/Sydney",
        country: "AU",
        languages: &["en"],
        lat: -33.8688,
        lon: 151.2093,
    },
    TimezoneFacts {
        timezone: "America/Toronto",
        country: "CA",
        languages: &["en", "fr"],
        lat: 43.6532,
        lon: -79.3832,
    },
];

/// Coarse upper bound (kilometres) on how far a persona's coordinates may sit from
/// its timezone's representative city before the pair is judged geographically
/// implausible. Sized to admit any metro *within* a single zone (e.g. San
/// Francisco coordinates under `America/Los_Angeles`, ~560 km) while still catching
/// gross cross-continent errors (e.g. New York coordinates under `Asia/Tokyo`,
/// ~10 800 km). The coordinate check is a coarse secondary guard; the
/// timezone↔country↔language agreement is the load-bearing signal.
const MAX_COORD_DISTANCE_KM: f64 = 3000.0;

/// Look up the built-in reference facts for an IANA timezone, or `None` if the
/// zone is not in the catalogue (the caller must treat that as *unknown*, never as
/// agreement).
#[must_use]
pub fn timezone_facts(timezone: &str) -> Option<&'static TimezoneFacts> {
    TIMEZONE_FACTS.iter().find(|f| f.timezone == timezone)
}

/// The ISO-3166 region subtag of a BCP-47 locale, uppercased, e.g. `"en-US"` →
/// `"US"`, `"de-DE"` → `"DE"`. Returns `None` for a language-only tag (`"en"`).
#[must_use]
fn locale_region(locale: &str) -> Option<String> {
    locale
        .split(['-', '_'])
        .nth(1)
        .filter(|r| r.len() == 2 && r.chars().all(|c| c.is_ascii_alphabetic()))
        .map(|r| r.to_ascii_uppercase())
}

/// The primary language subtag of a BCP-47 tag, lowercased: `"en-US"` → `"en"`,
/// `"ja"` → `"ja"`.
#[must_use]
fn language_subtag(tag: &str) -> String {
    tag.split(['-', '_'])
        .next()
        .unwrap_or(tag)
        .to_ascii_lowercase()
}

/// Great-circle distance between two lat/lon points in kilometres (haversine).
#[must_use]
fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let (dlat, dlon) = ((lat2 - lat1).to_radians(), (lon2 - lon1).to_radians());
    let a = (dlat / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dlon / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_KM * a.sqrt().asin()
}

/// One way a persona's own geo facts contradict each other.
#[derive(Debug, Clone, PartialEq)]
pub enum GeoIncoherence {
    /// The explicit egress/WebRTC country differs from the timezone's country.
    Country {
        /// Country the persona's timezone belongs to.
        timezone_country: String,
        /// Country derived from the single geo-region owner (proxy-geo/WebRTC).
        persona_country: String,
    },
    /// The locale's region subtag names a different country than the timezone.
    LocaleCountry {
        /// Country the persona's timezone belongs to.
        timezone_country: String,
        /// Region subtag carried by the persona's `locale`.
        locale_region: String,
    },
    /// The persona's primary `navigator.languages` entry is not a language of the
    /// timezone's country.
    Language {
        /// The persona's primary language subtag.
        primary_language: String,
        /// Languages the timezone's country is expected to use.
        timezone_languages: Vec<String>,
    },
    /// The coordinates are implausibly far from the timezone's region.
    Coordinates {
        /// Kilometres from the timezone's representative city.
        distance_km: f64,
        /// The timezone the coordinates were checked against.
        timezone: String,
    },
}

/// Verdict on a persona's INTERNAL geo-coherence (timezone vs locale vs language
/// vs coordinates) (independent of any egress).
#[derive(Debug, Clone, PartialEq)]
pub enum GeoCoherence {
    /// Timezone, locale, language, and coordinates all agree.
    Coherent,
    /// At least one of the persona's geo facts contradicts the others.
    Incoherent(Vec<GeoIncoherence>),
    /// The persona's timezone is not in the reference catalogue, so its
    /// locale/language/coordinates cannot be cross-checked. Explicitly NOT
    /// `Coherent`: an unknown zone is never read as agreement (Law 10). The
    /// operator should extend the Tier-B timezone catalogue to cover it.
    Unknown {
        /// The unrecognised timezone.
        timezone: String,
    },
}

impl GeoCoherence {
    /// Whether the persona's own geo facts are mutually coherent.
    #[must_use]
    pub const fn is_coherent(&self) -> bool {
        matches!(self, Self::Coherent)
    }
}

/// Check a persona's INTERNAL geo-coherence: its `timezone` must name a country
/// whose region matches the `locale`, whose languages include the persona's
/// primary language, and whose representative location is within
/// [`MAX_COORD_DISTANCE_KM`] of the persona's coordinates.
///
/// Returns [`GeoCoherence::Unknown`] (loud) for a timezone the reference does not
/// cover (never a silent pass).
#[must_use]
pub fn identity_geo_coherence(identity: &NavigatorProfile) -> GeoCoherence {
    let Some(facts) = timezone_facts(&identity.timezone) else {
        return GeoCoherence::Unknown {
            timezone: identity.timezone.clone(),
        };
    };

    let mut problems = Vec::new();

    // The single-owner geo-region country (proxy-geo / WebRTC) must match the
    // timezone's country.
    if !identity.country.is_empty() {
        let persona_country = identity.country.to_ascii_uppercase();
        if persona_country != facts.country {
            problems.push(GeoIncoherence::Country {
                timezone_country: facts.country.to_string(),
                persona_country,
            });
        }
    }

    // locale region (when present) must equal the timezone's country.
    if let Some(region) = locale_region(&identity.locale) {
        if region != facts.country {
            problems.push(GeoIncoherence::LocaleCountry {
                timezone_country: facts.country.to_string(),
                locale_region: region,
            });
        }
    }

    // The persona's PRIMARY language must be a language of the zone's country.
    if let Some(primary) = identity.languages.first() {
        let primary = language_subtag(primary);
        if !facts.languages.iter().any(|l| *l == primary) {
            problems.push(GeoIncoherence::Language {
                primary_language: primary,
                timezone_languages: facts.languages.iter().map(|l| (*l).to_string()).collect(),
            });
        }
    }

    // Coordinates must be plausibly within the zone's region.
    let distance = haversine_km(identity.latitude, identity.longitude, facts.lat, facts.lon);
    if distance > MAX_COORD_DISTANCE_KM {
        problems.push(GeoIncoherence::Coordinates {
            distance_km: distance,
            timezone: facts.timezone.to_string(),
        });
    }

    if problems.is_empty() {
        GeoCoherence::Coherent
    } else {
        GeoCoherence::Incoherent(problems)
    }
}

/// The geography of our actual egress, as the operator/proxy reports it. Every
/// field is optional: a `None` field is simply not cross-checked (it is never
/// treated as agreement). guise does NOT resolve these itself, the operator who
/// owns the proxy supplies the egress IP's country and, if known, the timezone it
/// geolocates to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservedEgressGeo {
    /// ISO-3166-1 alpha-2 country code the egress IP geolocates to.
    pub country: Option<String>,
    /// IANA timezone the egress IP geolocates to, if the operator resolved it.
    pub timezone: Option<String>,
}

impl ObservedEgressGeo {
    /// Whether any egress layer is present to cross-check.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.country.is_none() && self.timezone.is_none()
    }
}

/// One way a persona's claimed geography contradicts its actual egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressGeoMismatch {
    /// The persona's timezone country differs from the egress IP's country, the
    /// "timezone says New York, but you are egressing from Germany" tell.
    Country {
        /// Country the persona's timezone belongs to.
        persona_country: String,
        /// Country the egress IP geolocates to.
        egress_country: String,
    },
    /// The persona's timezone differs from the timezone the egress IP geolocates
    /// to (when the operator resolved the egress timezone).
    Timezone {
        /// Timezone the persona claims.
        persona_timezone: String,
        /// Timezone the egress IP geolocates to.
        egress_timezone: String,
    },
}

/// Verdict of probing a persona's claimed geography against its actual egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoSelfProbe {
    /// Every measured egress layer agrees with the persona's geography.
    Coherent,
    /// At least one egress layer contradicts the persona; each is named.
    Incoherent(Vec<EgressGeoMismatch>),
    /// No egress layer was supplied (an empty observation), explicitly NOT
    /// `Coherent`, so an absent measurement never reads as agreement (Law 10).
    Unmeasured,
}

impl GeoSelfProbe {
    /// Whether the egress agreed with the persona on every measured layer.
    #[must_use]
    pub const fn is_coherent(&self) -> bool {
        matches!(self, Self::Coherent)
    }
}

/// Probe a persona's claimed geography against the operator-supplied egress geo:
/// the country (and timezone, if resolved) the persona's `timezone` implies must
/// match the country (and timezone) the egress IP actually geolocates to.
///
/// This is the geo analogue of the Layer-2 wire self-probe: *detect "timezone
/// says US, but the IP says Germany" before a detector does*, and the direct
/// answer to the open R056/R057 finding (a persona's `America/Phoenix` timezone
/// against a proxy that egresses elsewhere). It compares only the layers the
/// observation supplies, returns [`GeoSelfProbe::Unmeasured`] when none are present
/// (never a silent pass), and surfaces every contradiction by name.
///
/// The persona's timezone country is resolved through [`timezone_facts`]; an
/// unknown persona timezone means the country layer cannot be compared (the
/// timezone layer is still compared by exact string, which needs no catalogue).
#[must_use]
pub fn persona_geo_self_probe(
    identity: &NavigatorProfile,
    observed: &ObservedEgressGeo,
) -> GeoSelfProbe {
    let mut mismatches = Vec::new();
    let mut compared = 0_usize;

    if let Some(egress_country) = observed.country.as_deref() {
        // The persona's country is the single-owner region country when present;
        // fall back to resolving it from the timezone catalogue for identities that
        // pre-date the country field.
        let persona_country = if identity.country.is_empty() {
            timezone_facts(&identity.timezone).map(|f| f.country)
        } else {
            Some(identity.country.as_str())
        };
        if let Some(persona_country) = persona_country {
            compared += 1;
            let egress_country = egress_country.to_ascii_uppercase();
            if persona_country != egress_country {
                mismatches.push(EgressGeoMismatch::Country {
                    persona_country: persona_country.to_string(),
                    egress_country,
                });
            }
        }
    }

    if let Some(egress_tz) = observed.timezone.as_deref() {
        compared += 1;
        if identity.timezone != egress_tz {
            mismatches.push(EgressGeoMismatch::Timezone {
                persona_timezone: identity.timezone.clone(),
                egress_timezone: egress_tz.to_string(),
            });
        }
    }

    if compared == 0 {
        GeoSelfProbe::Unmeasured
    } else if mismatches.is_empty() {
        GeoSelfProbe::Coherent
    } else {
        GeoSelfProbe::Incoherent(mismatches)
    }
}

#[cfg(test)]
#[path = "geo_coherence/tests.rs"]
mod tests;
