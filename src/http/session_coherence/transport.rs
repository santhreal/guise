//! Transport-layer coherence: resolving a persona's full TCP/IP + HTTP/2 +
//! header-order picture, and the pure-code predicate that asserts those layers
//! describe one `(browser, OS)` identity. The per-engine wire data this resolves
//! against lives in [`super::profiles`].

use super::profiles::{pair_for_profile, H2Profile, HeaderOrder};
use crate::fingerprint::{
    profile_os_network_stack, Ja4tError, OsNetworkStack, StealthProfile, UserAgentPlatform,
};

/// The full transport-layer fingerprint a persona must present coherently: the
/// TCP/IP SYN stack, the HTTP/2 SETTINGS profile, and the request-header
/// insertion order.
///
/// A real browser's three transport layers always agree; a persona that is
/// coherent at the HTTP/2 layer but ships a contradicting TCP/IP stack (e.g. a
/// Windows browser profile egressing from a Linux host) is still fingerprintable
/// at the layer below HTTP. This bundle is the single resolution point so a
/// caller sees all three layers at once rather than checking them piecemeal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportCoherence {
    /// TCP/IP SYN fingerprint of the persona's claimed OS.
    pub network: OsNetworkStack,
    /// HTTP/2 SETTINGS profile for the persona's browser family.
    pub h2: H2Profile,
    /// Request-header insertion order for the persona's browser family.
    pub header_order: HeaderOrder,
}

impl TransportCoherence {
    /// The persona's expected **JA4T** (FoxIO TCP-client fingerprint), delegating
    /// to the resolved TCP/IP stack, the wire string a detector computes off the
    /// persona's SYN. See [`OsNetworkStack::ja4t`] for the format and the `*`
    /// wildcard used for autotuned-window OS families.
    ///
    /// # Errors
    ///
    /// Propagates [`Ja4tError`] if the stack's options layout carries an option
    /// with no canonical IANA kind (fails closed, never a silent partial JA4T).
    pub fn ja4t(&self) -> Result<String, Ja4tError> {
        self.network.ja4t()
    }
}

/// Resolve the persona's full transport-coherence picture across all three
/// layers (TCP/IP, HTTP/2, header order).
///
/// Returns `None` for personas with no modeled HTTP/2 + header-order profile
/// (e.g. IE11), matching [`pair_for_profile`]. The network layer alone is
/// available for *every* persona via [`profile_os_network_stack`].
#[must_use]
pub fn transport_coherence_for_profile(profile: StealthProfile) -> Option<TransportCoherence> {
    let (header_order, h2) = pair_for_profile(profile)?;
    Some(TransportCoherence {
        network: profile_os_network_stack(profile),
        h2,
        header_order,
    })
}

/// The canonical transport-layer family (`"chrome"`/`"firefox"`/`"safari"`) a
/// browser family emits, or `None` for browsers with no modeled transport
/// profile (Internet Explorer) or an unrecognised UA.
///
/// Chromium-derived brands (Edge, Opera, Brave, Samsung Internet) all share the
/// Chrome transport profile, so they fold into `"chrome"`.
#[must_use]
pub fn transport_family_for_browser(
    browser: crate::fingerprint::UserAgentBrowser,
) -> Option<&'static str> {
    use crate::fingerprint::UserAgentBrowser::{
        Chrome, Edge, Firefox, InternetExplorer, Opera, Safari, SamsungInternet, Unknown,
    };
    match browser {
        Chrome | Edge | Opera | SamsungInternet => Some("chrome"),
        Firefox => Some("firefox"),
        Safari => Some("safari"),
        InternetExplorer | Unknown => None,
    }
}

/// Which transport layer breaks a persona's single-identity coherence.
///
/// The enclosing `TransportIncoherence` already conveys "mismatch"; each variant
/// names the *layer* that disagrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportIncoherence {
    /// The TCP/IP stack's OS disagrees with the persona's claimed (UA) OS.
    Os {
        /// OS family the User-Agent claims.
        ua_os: UserAgentPlatform,
        /// OS family the TCP/IP stack would emit.
        tcp_os: UserAgentPlatform,
    },
    /// HTTP/2 and request-header-order families disagree with each other.
    HttpFamily {
        /// HTTP/2 SETTINGS profile family.
        h2: &'static str,
        /// Request-header-order family.
        header_order: &'static str,
    },
    /// The HTTP transport family disagrees with the persona's browser family.
    BrowserFamily {
        /// Family implied by the persona's User-Agent browser.
        browser_family: &'static str,
        /// Family of the persona's HTTP transport profile.
        http_family: &'static str,
    },
    /// The TLS impersonation family disagrees with the HTTP transport family
    /// the "TLS says Firefox, UA says Chrome" tell. Only checked under the `http`
    /// feature (the TLS impersonate catalogue lives there).
    TlsFamily {
        /// Family of the persona's default TLS impersonation profile.
        tls_family: &'static str,
        /// Family of the persona's HTTP transport profile.
        http_family: &'static str,
    },
}

/// Assert a persona's transport layers all describe one `(browser, OS)`
/// identity (the pure-code half of the G022 coherence gate).
///
/// Checks, and fails loud on the first disagreement:
/// 1. **UA-OS == TCP-OS**: the persona's claimed OS matches its TCP/IP stack.
/// 2. **HTTP/2 family == header-order family**: the two HTTP layers agree.
/// 3. **HTTP family == UA browser family**: the HTTP transport matches the
///    browser the User-Agent claims (a Firefox UA must not carry Chrome's H2).
///
/// Returns `Ok(())` for a self-coherent persona. A persona with no HTTP
/// transport profile (IE11) is `Ok(())` for the layers that exist, only its
/// TCP stack, which has nothing to cross-check against. The TLS-OS and
/// timezone↔IP arms of the full gate need the live transport and are checked
/// separately. This is primarily a *regression guard*: every shipped persona
/// passes today, so a future persona wired to the wrong family fails the
/// property test rather than leaking an incoherent fingerprint in production.
pub fn persona_transport_coherence(profile: StealthProfile) -> Result<(), TransportIncoherence> {
    let ua_os = crate::fingerprint::profile_platform(profile);
    let tcp_os = profile_os_network_stack(profile).os;
    if ua_os != tcp_os {
        return Err(TransportIncoherence::Os { ua_os, tcp_os });
    }

    if let Some((header_order, h2)) = pair_for_profile(profile) {
        if h2.family != header_order.family {
            return Err(TransportIncoherence::HttpFamily {
                h2: h2.family,
                header_order: header_order.family,
            });
        }
        let browser =
            crate::fingerprint::user_agent_facts(crate::fingerprint::profile_user_agent(profile))
                .browser;
        if let Some(expected) = transport_family_for_browser(browser) {
            if expected != h2.family {
                return Err(TransportIncoherence::BrowserFamily {
                    browser_family: expected,
                    http_family: h2.family,
                });
            }
        }

        // TLS arm (G062): the persona's default wire-impersonation family must
        // agree with its HTTP family too. Gated on `http`, where the TLS
        // impersonate catalogue lives; when that feature is off the gate checks
        // the three layers that are compiled in.
        #[cfg(feature = "http")]
        {
            use crate::fingerprint::tls_profiles::{
                default_impersonate_profile_for_stealth_profile, impersonate_profile_family,
            };
            let tls = default_impersonate_profile_for_stealth_profile(profile);
            if let Some(tls_family) = impersonate_profile_family(tls) {
                if tls_family != h2.family {
                    return Err(TransportIncoherence::TlsFamily {
                        tls_family,
                        http_family: h2.family,
                    });
                }
            }
        }
    }
    Ok(())
}
