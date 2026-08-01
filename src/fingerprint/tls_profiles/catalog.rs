//! TLS ClientHello profile data catalogue.
//!
//! This module is the *data* half of [`super`] (`fingerprint::tls_profiles`):
//! the primitive cipher / extension / curve / signature-algorithm slices and the
//! nine browser-/client-family [`TlsProfile`] constants assembled from them, plus
//! the [`ALL_PROFILES`] index. The query, build, and JA3/JA4 computation logic
//! lives in the parent module. Splitting the static catalogue from the logic
//! keeps each file under the Law-5 modularity bound without changing any field.
//!
//! Visibility contract: the seven profiles named directly by
//! `profile_for_stealth_profile` and the `ALL_PROFILES` index are `pub(crate)`
//! so the parent's query helpers can reference them; the two non-browser
//! profiles (`CURL_8_OPENSSL`, `PYTHON_REQUESTS`) and every primitive slice stay
//! private (they reach the parent only through `ALL_PROFILES`).

use super::TlsProfile;

const TLS13_CHROME_CIPHERS: &[u16] = &[0x1301, 0x1302, 0x1303];
const TLS13_FIREFOX_CIPHERS: &[u16] = &[0x1301, 0x1303, 0x1302];

const CHROME_EXTENSIONS: &[u16] = &[
    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0012, 0x0033, 0x002b, 0x000d,
    0x002d, 0x001c, 0x001b,
];

const FIREFOX_EXTENSIONS: &[u16] = &[
    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0033, 0x002b, 0x002d,
    0x001c, 0x0015,
];

const MODERN_CURVES: &[u16] = &[0x001d, 0x0017, 0x0018];
const EC_POINT_FORMATS: &[u8] = &[0x00];

const CHROME_SIG_ALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

// ── Measured Chrome 146 ClientHello (real wire data, current stable) ──
//
// Captured live 2026-06-12 by driving the host's stock Chrome/146 to
// `tls.peet.ws`. The 15-cipher BoringSSL list (GREASE-stripped); the
// 17-extension list carries the modern Chrome set a simplified placeholder
// dropped: ECH (0xfe0d), ALPS at its NEW codepoint 0x44cd, pre_shared_key
// (0x0029), compress_certificate (0x001b), session_ticket (0x0023). `compute_ja4`
// over this profile reproduces the measured, cross-connection-STABLE JA4
// `t13d1517h2_8daaf6152771_b6f405a00624` byte-for-byte (sigalgs == `CHROME_SIG_ALGS`,
// reused). Chrome's signature scheme list is its 8-entry set, also reused.
//
// **JA3 caveat:** Chrome shuffles its TLS extension ORDER per connection (RFC-8701),
// so `expected_ja3` self-checksums the ONE sampled wire order below, it is a
// representative sample, NOT a fixed match key (proven: 3 captures → 3 distinct JA3
// hashes, 1 identical JA4). Match Chrome on JA4. GREASE is emitted on the wire
// (`include_grease: true`) but excluded from JA3/JA4 by definition.
const CHROME_146_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
const CHROME_146_EXTENSIONS: &[u16] = &[
    0x44cd, 0x0000, 0x002d, 0x000b, 0xfe0d, 0x000a, 0x002b, 0x000d, 0xff01, 0x0005, 0x0033, 0x0010,
    0x0012, 0x001b, 0x0017, 0x0023, 0x0029,
];
// Leads with the post-quantum hybrid X25519MLKEM768 (0x11ec), then X25519,
// P-256, P-384: Chrome's PQ-by-default group order.
const CHROME_146_GROUPS: &[u16] = &[0x11ec, 0x001d, 0x0017, 0x0018];

// Firefox advertises 11 signature algorithms: the 9 modern ECDSA / RSA-PSS /
// RSA-PKCS1 schemes followed by the two legacy SHA-1 schemes (ecdsa_sha1 0x0203,
// rsa_pkcs1_sha1 0x0201). The SHA-1 pair is load-bearing for the JA4 extension
// hash, omitting it produced a JA4 that diverged from real Firefox-150 (proven
// by `ja3_and_ja4_for_firefox_150_match_the_measured_wire_values`, which only
// reproduces the measured ext-hash `e6dcd7ae0a9e` with all 11 present).
const FIREFOX_SIG_ALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];

// ── Measured Firefox-150 ClientHello (real wire data) ──
//
// These three slices are the EXACT cipher, extension, and supported-group lists
// from a real `tls.peet.ws` capture of stock Firefox-150 on Linux, the same
// fields the `firefox-150-linux` cluster target and the
// `ja3::tests::firefox_150_fields` unit vector carry. They build `FIREFOX_150`
// below, the byte-accurate modal real-Firefox shape:
// `compute_ja3_string`/`compute_ja4_string` over this profile reproduce the
// measured `0e76c7e9…` JA3 and `t13d1717h2_5b57614c22b0_e6dcd7ae0a9e` JA4, the
// values millions of real Firefox users share, not a distinctive (trackable)
// one (G005 exact lists, G007 FF-authentic extension order, G049/G050
// anti-uniqueness).
//
// **OS-independent.** Firefox's NSS stack emits the identical ClientHello on
// Linux/Windows/macOS for a given version (only the TCP/IP layer is OS-specific),
// so `FirefoxLinux` AND `FirefoxWindows` both map to this one profile; the OS
// distinction lives in the persona's UA/platform, not in the ClientHello.
//
// **Version stability is partial, measured, not assumed.** The extension order,
// supported groups, and signature algorithms are stable across the recent stable
// line (X25519MLKEM768 landed in FF-132, ECH in FF-118), so the JA4 `_c` ext hash
// `e6dcd7ae0a9e` holds 132→151. The CIPHER list is NOT fully stable: a live
// FF-151 capture (2026-06-12, see `FIREFOX_151_CIPHERS`) shows Firefox dropped
// `0xc009` at 151 (17→16 ciphers), moving the JA3 and the JA4 `_b` cipher hash.
// This 17-cipher shape is the FF-150 / Camoufox-150 value the desktop persona's
// reynard engine actually emits, and matches any pre-151 stable UA, the
// `Firefox/150` persona emits exactly these bytes, a coherent UA-vs-JA3 pair;
// `FIREFOX_151` carries the current-stable 16-cipher offer for transports on a
// 151-era engine.
const FIREFOX_150_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];

// ── Measured Firefox 151 ClientHello (real wire data, current stable) ──
//
// Captured live 2026-06-12 by driving the host's stock `Firefox/151.0` to
// `tls.peet.ws/api/all`. It is FIREFOX_150's cipher list MINUS one suite:
// Firefox dropped `0xc009` (TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, a legacy CBC
// suite) at 151, so the offer shrank 17→16 ciphers. EVERYTHING else is
// byte-identical to FF-150, same extension order, same supported groups, same
// signature algorithms, which is why `FIREFOX_151` reuses those slices and the
// measured JA4 `_c` extension hash is UNCHANGED (`e6dcd7ae0a9e`); only the cipher
// count (`t13d17…`→`t13d16…`) and the JA4 `_b` cipher hash
// (`5b57614c22b0`→`86a278354501`) move. JA3 `f19d54c853fffdd9eeab77ae607448e9`,
// JA4 `t13d1617h2_86a278354501_e6dcd7ae0a9e`.
//
// This is the modal CURRENT-stable Firefox shape. It is NOT the desktop-Firefox
// persona's TLS: that persona is served by reynard (Camoufox-150, a Firefox-150
// engine) which emits the 17-cipher FF-150 shape, so the persona stays on
// `FIREFOX_150` for engine coherence (claiming FF-151's 16-cipher offer while the
// reynard engine sends 17 would be the tell). `FIREFOX_151` is the selectable
// target for guise's own HTTP transport disguise and the next reynard rebase.
const FIREFOX_151_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];

// Wire order is the JA3/JA4 discriminator (G007). Carries the modern Firefox
// extensions a simplified list omitted: delegated_credentials (0x0022, G057),
// record_size_limit (0x001c, G057), compress_certificate (0x001b, G056),
// Encrypted Client Hello (0xfe0d, G008), and pre_shared_key (0x0029).
const FIREFOX_150_EXTENSIONS: &[u16] = &[
    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x0022, 0x0012, 0x0033, 0x002b, 0x000d,
    0x002d, 0x001c, 0x001b, 0xfe0d, 0x0029,
];

// Leads with the post-quantum hybrid X25519MLKEM768 (0x11ec), the group modern
// Firefox offers first (then the classical curves and the two FFDHE groups).
const FIREFOX_150_GROUPS: &[u16] = &[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101];

// ── Measured curl 8.5.0 / OpenSSL 3.0.13 ClientHello (real wire data) ──
//
// Captured live 2026-06-12 against `tls.peet.ws/api/all` from the host's own
// `curl 8.5.0 (OpenSSL/3.0.13)`: the EXACT build this profile models, so the
// fields below ARE the wire bytes, not an approximation. JA3
// `0149f47eabf9a20d0893e2a44e5a6323`; JA4 `t13d3112h2_e8f1e7e78f70_375ca2c5e164`
// (peet's value, see the divergence note on `CURL_8_OPENSSL` below). The
// OpenSSL default offer is much wider than a browser's TLS-1.3-only suite: 31
// ciphers spanning TLS 1.3 + the full ECDHE/DHE 1.2 ladder down to legacy
// AES-CBC and `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (0x00ff).
//
// These five `CURL_8_OPENSSL_*` slices are really the OpenSSL-3.0.13 DEFAULT
// offer, so `PYTHON_REQUESTS` (requests 2.34 / urllib3 2.7, which links the same
// system OpenSSL) reuses them verbatim, a live capture confirmed python-requests
// emits the byte-identical ClientHello and the SAME JA3 `0149f47e…`; the two
// reference clients differ ONLY in ALPN (curl offers h2, urllib3 is http/1.1-only),
// hence a different JA4 `h2`/`h1` digit (`python_requests_shares_curl_openssl3_ja3`).
const CURL_8_OPENSSL_CIPHERS: &[u16] = &[
    0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa, 0xc02b, 0xc02f, 0x009e,
    0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067, 0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033,
    0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff,
];

// Wire order (the JA3/JA4 discriminator). Carries the OpenSSL extensions a
// simplified list omitted: encrypt_then_mac (0x0016), extended_master_secret
// (0x0017), post_handshake_auth (0x0031), and the RFC-7685 padding extension
// (0x0015) OpenSSL appends to round the ClientHello size.
const CURL_8_OPENSSL_EXTENSIONS: &[u16] = &[
    0x0000, 0x000b, 0x000a, 0x0010, 0x0016, 0x0017, 0x0031, 0x000d, 0x002b, 0x002d, 0x0033, 0x0015,
];

// 10 supported groups: the 5 named curves (X25519, P-256, X448, P-521, P-384)
// then the 5 FFDHE groups (ffdhe2048..ffdhe8192). OpenSSL still offers finite-
// field DH, unlike browsers.
const CURL_8_OPENSSL_GROUPS: &[u16] = &[
    0x001d, 0x0017, 0x001e, 0x0019, 0x0018, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
];

// OpenSSL advertises all three legacy EC point formats (uncompressed +
// ansiX962_compressed_prime/char2), where browsers send only uncompressed.
const CURL_8_OPENSSL_POINT_FORMATS: &[u8] = &[0x00, 0x01, 0x02];

// 20 signature algorithms (the JA4 `_c` tail): ECDSA/EdDSA/RSA-PSS/RSA-PKCS1
// modern schemes followed by OpenSSL's legacy SHA-2 `0x03xx`/`0x04xx`-`0x06xx`
// pairs. Offered order is preserved (JA4 does not sort sigalgs).
const CURL_8_OPENSSL_SIG_ALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401,
    0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602,
];

/// Every shipped profile is a TLS 1.3 client that pins its legacy ClientHello
/// version to 0x0303 (TLS 1.2) for middlebox compatibility and negotiates 1.3
/// via the supported_versions extension. Highest first.
const TLS13_SUPPORTED_VERSIONS: &[u16] = &[0x0304, 0x0303];

// The byte-accurate measured Chrome 146 (current stable). Its `compute_ja4`
// reproduces the real `t13d1517h2_8daaf6152771_b6f405a00624`; `expected_ja3` is
// the self-checksum of the sampled extension order (see the JA3 caveat above).
pub(crate) const CHROME_146: TlsProfile = TlsProfile {
    name: "Chrome 146",
    tls_version: 0x0303,
    cipher_suites: CHROME_146_CIPHERS,
    extensions: CHROME_146_EXTENSIONS,
    elliptic_curves: CHROME_146_GROUPS,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "9c713794cc9790422a2bc435e7038fbf",
    signature_algorithms: CHROME_SIG_ALGS,
    include_grease: true,
    supported_versions: TLS13_SUPPORTED_VERSIONS,
};

pub(crate) const CHROME_122: TlsProfile = TlsProfile {
    name: "Chrome 122 / Windows 11",
    tls_version: 0x0303,
    cipher_suites: TLS13_CHROME_CIPHERS,
    extensions: CHROME_EXTENSIONS,
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "34145283fb0bab20d333c7ee0cc6cd3e",
    signature_algorithms: CHROME_SIG_ALGS,
    include_grease: true,
    supported_versions: TLS13_SUPPORTED_VERSIONS,
};

pub(crate) const CHROME_120: TlsProfile = TlsProfile {
    name: "Chrome 120 / macOS 14",
    tls_version: 0x0303,
    cipher_suites: TLS13_CHROME_CIPHERS,
    extensions: CHROME_EXTENSIONS,
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "34145283fb0bab20d333c7ee0cc6cd3e",
    signature_algorithms: CHROME_SIG_ALGS,
    include_grease: true,
    supported_versions: TLS13_SUPPORTED_VERSIONS,
};

// The desktop-Firefox personas' TLS entry: the byte-accurate measured FF-150
// ClientHello (OS-independent, see the slice doc above). Unlike the simplified
// profiles, its `expected_ja3` is BOTH the self-checksum AND the real measured
// JA3, because the fields ARE the measured wire shape, the two converge (see
// `firefox_linux_profile_is_the_measured_ff150_modal_wire_shape`).
pub(crate) const FIREFOX_150: TlsProfile = TlsProfile {
    name: "Firefox 150",
    tls_version: 0x0303,
    cipher_suites: FIREFOX_150_CIPHERS,
    extensions: FIREFOX_150_EXTENSIONS,
    elliptic_curves: FIREFOX_150_GROUPS,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "0e76c7e9d06fa0e211b1827687dd8f43",
    signature_algorithms: FIREFOX_SIG_ALGS,
    include_grease: false,
    supported_versions: TLS13_SUPPORTED_VERSIONS,
};

// The current-stable Firefox shape (measured FF-151, see `FIREFOX_151_CIPHERS`).
// Reuses FF-150's extension/group/sigalg slices (unchanged across 150→151) and
// differs only by the dropped `0xc009` cipher. `expected_ja3` is BOTH the
// self-checksum AND the real measured value (`firefox_151_is_the_measured_current_stable_shape`).
pub(crate) const FIREFOX_151: TlsProfile = TlsProfile {
    name: "Firefox 151",
    tls_version: 0x0303,
    cipher_suites: FIREFOX_151_CIPHERS,
    extensions: FIREFOX_150_EXTENSIONS,
    elliptic_curves: FIREFOX_150_GROUPS,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "f19d54c853fffdd9eeab77ae607448e9",
    signature_algorithms: FIREFOX_SIG_ALGS,
    include_grease: false,
    supported_versions: TLS13_SUPPORTED_VERSIONS,
};

pub(crate) const FIREFOX_115_ESR: TlsProfile = TlsProfile {
    name: "Firefox 115 ESR / Windows 10",
    tls_version: 0x0303,
    cipher_suites: TLS13_FIREFOX_CIPHERS,
    extensions: FIREFOX_EXTENSIONS,
    elliptic_curves: MODERN_CURVES,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "384ed43bffc9b99525a25fa1bc6d607e",
    signature_algorithms: FIREFOX_SIG_ALGS,
    include_grease: false,
    supported_versions: TLS13_SUPPORTED_VERSIONS,
};

// ── Measured Safari 18 / macOS ClientHello (real wire data) ──
//
// Captured 2026-06-13 by driving the BoringSSL `StealthClient` (Safari18
// emulation, whose TLS ClientHello is browser-specific, proven by the
// Chrome/Firefox cipher-hashes matching guise exactly in the live peet gate) to
// `tls.peet.ws/api/all`. The 20-cipher list (no GREASE. Apple's coretls does not
// GREASE, unlike Chrome's BoringSSL) and the 14-extension list reproduce the
// measured JA3 hash `773906b0efdefa24a7f2b8eb6985bf37` and the JA4 cipher-hash
// `a09f3c656075` byte-for-byte (`safari_18_profile_reproduces_the_measured_wire_
// fingerprint`). This REPLACES the prior Chrome-borrowed placeholder (which lifted
// `TLS13_CHROME_CIPHERS`/`CHROME_EXTENSIONS` and could never emit a real Safari
// shape). Curves add P-521 (0x0019) over the 3-group `MODERN_CURVES`, so Safari
// carries its own group list. (The H2 pseudo-header order is NOT taken from this
// source, wreq's Safari H2 order coincides with curl's nghttp2 default, so it is
// not authoritative; only the TLS ClientHello is used here.)
const SAFARI_18_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009, 0xc014,
    0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];
const SAFARI_18_EXTENSIONS: &[u16] = &[
    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b,
    0x001b, 0x0015,
];
// X25519, P-256, P-384, P-521: Safari advertises four groups (adds P-521).
const SAFARI_18_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019];
// Safari's 10 signature algorithms (ECDSA / RSA-PSS / RSA-PKCS1, incl. the legacy
// SHA-1 pair). peet rendered a duplicate `0805` in its raw view; the de-duplicated
// real list is used here.
const SAFARI_18_SIG_ALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];

pub(crate) const SAFARI_18: TlsProfile = TlsProfile {
    name: "Safari 18 / macOS",
    tls_version: 0x0303,
    cipher_suites: SAFARI_18_CIPHERS,
    extensions: SAFARI_18_EXTENSIONS,
    elliptic_curves: SAFARI_18_GROUPS,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "773906b0efdefa24a7f2b8eb6985bf37",
    signature_algorithms: SAFARI_18_SIG_ALGS,
    include_grease: false,
    supported_versions: TLS13_SUPPORTED_VERSIONS,
};

// The byte-accurate measured curl 8.5 / OpenSSL 3.0.13 ClientHello (see the
// `CURL_8_OPENSSL_*` slices above). Like `FIREFOX_150`, its `expected_ja3` is
// BOTH the self-checksum AND the real measured JA3, the fields ARE the wire
// shape, so `compute_ja3_string` over them reproduces the value tls.peet.ws
// computed for this exact curl build (`curl_8_openssl_is_the_measured_wire_shape`).
//
// JA4 note (a real, documented oracle divergence. NOT a bug to "fix"): this
// ClientHello carries the RFC-7685 padding extension (0x0015). The published
// FoxIO JA4 spec and threatrelay's reference keep padding in the sorted JA4_c
// hash (only SNI/ALPN are excluded), so `compute_ja4_string` here yields the
// spec-conformant `t13d3112h2_e8f1e7e78f70_b26ce05bbdd6`; tls.peet.ws instead
// drops padding and reports `…_375ca2c5e164`. guise follows the published spec
// (matching Cloudflare/Akamai-class detectors that implement it), and
// `curl_ja4_follows_the_published_spec_padding_rule` pins both values so the
// divergence is recorded, not silently resolved. No shipped browser persona
// sends 0x0015, so this never affects a stealth target's JA4.
const CURL_8_OPENSSL: TlsProfile = TlsProfile {
    name: "curl 8 / OpenSSL 3",
    tls_version: 0x0303,
    cipher_suites: CURL_8_OPENSSL_CIPHERS,
    extensions: CURL_8_OPENSSL_EXTENSIONS,
    elliptic_curves: CURL_8_OPENSSL_GROUPS,
    ec_point_formats: CURL_8_OPENSSL_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "0149f47eabf9a20d0893e2a44e5a6323",
    signature_algorithms: CURL_8_OPENSSL_SIG_ALGS,
    include_grease: false,
    supported_versions: TLS13_SUPPORTED_VERSIONS,
};

// ── Measured Safari 18 / iPadOS·iOS ClientHello (real wire data) ──
//
// Captured 2026-06-13 by driving the BoringSSL `StealthClient` (`SafariIpad18`
// emulation) to `tls.peet.ws/api/all`. The measured iPad-Safari-18 ClientHello is
// BYTE-FOR-BYTE IDENTICAL to the desktop `SAFARI_18` capture, same JA3 hash
// `773906b0efdefa24a7f2b8eb6985bf37`, same 20-cipher list, same 14 extensions
// (incl. the 0x0015 padding ext), same 4 groups (incl. P-521 0x0019), same 10
// sigalgs. Apple ships ONE coretls stack across macOS/iPadOS/iOS for a given
// Safari major, so the TLS layer does not encode the OS; the iPhone/iPad
// distinction lives in the User-Agent + HTTP/2 + JS layers, which guise models
// separately. This profile therefore REUSES the measured `SAFARI_18` wire slices
// (exactly as `PYTHON_REQUESTS` reuses `CURL_8_OPENSSL`'s byte-identical OpenSSL
// shape) rather than duplicating the literals, and carries an iOS-coherent
// `name` so an iPhone/iPad persona never reports a "macOS" TLS profile. This
// REPLACES the prior Chrome-borrowed `SAFARI_IOS_17` placeholder (which lifted
// `TLS13_CHROME_CIPHERS`/`CHROME_SIG_ALGS`/`MODERN_CURVES` + GREASE and could
// never emit a real Safari shape). Verified by
// `safari_ios_18_profile_reproduces_the_measured_wire_fingerprint`.
pub(crate) const SAFARI_IOS_18: TlsProfile = TlsProfile {
    name: "Safari 18 / iOS",
    tls_version: 0x0303,
    cipher_suites: SAFARI_18_CIPHERS,
    extensions: SAFARI_18_EXTENSIONS,
    elliptic_curves: SAFARI_18_GROUPS,
    ec_point_formats: EC_POINT_FORMATS,
    alpn_protocols: &["h2", "http/1.1"],
    expected_ja3: "773906b0efdefa24a7f2b8eb6985bf37",
    signature_algorithms: SAFARI_18_SIG_ALGS,
    include_grease: false,
    supported_versions: TLS13_SUPPORTED_VERSIONS,
};

// Measured `requests 2.34.2 / urllib3 2.7.0` ClientHello (live 2026-06-12). Both
// link the host's OpenSSL 3.0.13, so the cipher/extension/group/sigalg/point-
// format wire shape is BYTE-IDENTICAL to `CURL_8_OPENSSL`: and the JA3 is the
// same `0149f47e…` (JA3 does not encode ALPN). The ONE measured difference is
// ALPN: urllib3 is HTTP/1.1-only, so it advertises `http/1.1` alone (no `h2`),
// which is why its JA4 carries the `h1` ALPN digit (`t13d3112h1_…`) where curl
// carries `h2`. Reuses the OpenSSL slices rather than duplicating them.
const PYTHON_REQUESTS: TlsProfile = TlsProfile {
    name: "Python requests / urllib3 (OpenSSL 3.0.13)",
    tls_version: 0x0303,
    cipher_suites: CURL_8_OPENSSL_CIPHERS,
    extensions: CURL_8_OPENSSL_EXTENSIONS,
    elliptic_curves: CURL_8_OPENSSL_GROUPS,
    ec_point_formats: CURL_8_OPENSSL_POINT_FORMATS,
    alpn_protocols: &["http/1.1"],
    expected_ja3: "0149f47eabf9a20d0893e2a44e5a6323",
    signature_algorithms: CURL_8_OPENSSL_SIG_ALGS,
    include_grease: false,
    supported_versions: TLS13_SUPPORTED_VERSIONS,
};

pub(crate) const ALL_PROFILES: &[TlsProfile] = &[
    CHROME_146,
    CHROME_122,
    CHROME_120,
    FIREFOX_150,
    FIREFOX_151,
    FIREFOX_115_ESR,
    SAFARI_18,
    CURL_8_OPENSSL,
    SAFARI_IOS_18,
    PYTHON_REQUESTS,
];
