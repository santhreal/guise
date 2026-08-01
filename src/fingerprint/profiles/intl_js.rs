//! Intl + Date persona spoof: pin the **locale** and **timezone** the browser
//! presents through `Intl.*`, `Date`, `Number`, and `String` (R056).
//!
//! Without this, an injected persona pins its `navigator` surfaces but the browser
//! still reports the **host** locale and timezone through the ECMAScript
//! Internationalization API: `Intl.DateTimeFormat().resolvedOptions().{locale,
//! timeZone}`, `Intl.NumberFormat`/`Collator`, `Number.prototype.toLocaleString`,
//! `Date.prototype.toLocale*`, `Date.prototype.getTimezoneOffset`: a loud
//! incoherence (a `de-DE` persona on an `America/Phoenix` host) that CreepJS and
//! FingerprintJS weight heavily.
//!
//! The spoof is **sound or it is nothing**: a partial override (e.g. forcing
//! `resolvedOptions().timeZone` while `format()` still renders host-local time, or
//! a fixed offset that ignores DST, or a locale on `resolvedOptions` but not on
//! `Number.toLocaleString`) is itself a tell. So the persona locale/timezone are
//! injected into the REAL `Intl` constructors (not faked in `resolvedOptions`) so
//! resolution AND formatting genuinely agree, and every offset/zone-name is
//! computed from the browser's OWN ICU for the target zone. DST-correct for any
//! date. The override set is the full consistent group across `Intl.*`, `Date`,
//! `Number`, and `String`.
//!
//! Soundness is proven by an out-of-process oracle: [`intl_spoof_js`] is
//! self-contained (touches only `Intl`/`Date`/`Number`/`String`, all present in
//! Node), so the test suite runs it under `TZ=America/Phoenix node` and asserts
//! every surface reports the *persona* locale/zone (not the host) and agrees with
//! the others, across a summer (DST) and winter date and both hemispheres.

use serde_json::json;

/// The default IANA timezone for a persona, derived from its primary language tag
/// so the emitted timezone is geographically coherent with `navigator.languages`
/// (the same agreement [`crate::fingerprint::geo_coherence`] enforces). A
/// region-qualified tag (`en-GB`) is matched before the bare language (`en`); an
/// unrecognised tag falls back to `America/New_York` (the `en` default), never to
/// the host zone (a coherent default beats leaking the host).
#[must_use]
pub fn default_timezone_for_locale(primary_language: &str) -> &'static str {
    let lower = primary_language.to_ascii_lowercase();
    let by_region = match lower.as_str() {
        "en-us" => Some("America/New_York"),
        "en-gb" => Some("Europe/London"),
        "en-ca" | "fr-ca" => Some("America/Toronto"),
        "en-au" => Some("Australia/Sydney"),
        "en-in" | "hi-in" => Some("Asia/Kolkata"),
        "de-de" | "de-at" => Some("Europe/Berlin"),
        "fr-fr" => Some("Europe/Paris"),
        "es-es" => Some("Europe/Madrid"),
        "nl-nl" => Some("Europe/Amsterdam"),
        "ja-jp" => Some("Asia/Tokyo"),
        "zh-cn" => Some("Asia/Shanghai"),
        _ => None,
    };
    if let Some(tz) = by_region {
        return tz;
    }
    match lower.split(['-', '_']).next().unwrap_or(&lower) {
        "de" => "Europe/Berlin",
        "fr" => "Europe/Paris",
        "es" => "Europe/Madrid",
        "nl" => "Europe/Amsterdam",
        "ja" => "Asia/Tokyo",
        "zh" => "Asia/Shanghai",
        "hi" => "Asia/Kolkata",
        _ => "America/New_York",
    }
}

/// Generate the self-contained Intl/Date spoof override statements for a persona
/// `primary_locale` (BCP-47, e.g. `en-US`) and IANA `timezone`. The result uses
/// `__seal` when it is in scope (the per-profile stealth IIFE provides it for
/// native-`toString` camouflage) and degrades to an identity seal otherwise, so it
/// also runs stand-alone under Node for the soundness oracle.
#[must_use]
pub fn intl_spoof_js(primary_locale: &str, timezone: &str) -> String {
    let locale = json!(primary_locale);
    let tz = json!(timezone);
    format!(
        r#"
    /* Intl + Date (R056): pin the persona's LOCALE and TIMEZONE so the browser
       stops leaking the HOST locale/zone. Locale + zone are injected into the REAL
       Intl constructors (format AND resolvedOptions genuinely use them), and every
       offset/zone-name comes from the browser's OWN ICU for the target zone
       (DST-correct for every date), so resolvedOptions / format / getTimezoneOffset
       / the Date+Number+String locale methods are mutually consistent (a partial
       spoof would itself be a tell). */
    try {{
        const __tzseal = (typeof __seal === 'function') ? __seal : (f) => f;
        const __LOCALE = {locale};
        const __TZ = {tz};
        const __OrigDTF = Intl.DateTimeFormat;
        const __OrigDate = Date;
        const __WD = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
        const __MO = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
        const __wallFmt = new __OrigDTF('en-US', {{ timeZone: __TZ, hourCycle: 'h23',
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit' }});
        const __nameFmt = new __OrigDTF('en-US', {{ timeZone: __TZ, timeZoneName: 'long', year: 'numeric' }});
        const __wallParts = (date) => {{
            const o = {{}};
            for (const p of __wallFmt.formatToParts(date)) if (p.type !== 'literal') o[p.type] = p.value;
            return o;
        }};
        // getTimezoneOffset() === (UTC - local) in minutes (positive west of UTC).
        const __offMin = (date) => {{
            const t = date.getTime();
            if (!isFinite(t)) return NaN;
            const p = __wallParts(date);
            const h = (p.hour === '24') ? 0 : +p.hour;
            const asUTC = __OrigDate.UTC(+p.year, +p.month - 1, +p.day, h, +p.minute, +p.second);
            return Math.round((t - asUTC) / 60000);
        }};
        const __zoneLong = (date) => {{
            try {{ for (const p of __nameFmt.formatToParts(date)) if (p.type === 'timeZoneName') return p.value; }} catch (_) {{}}
            return '';
        }};
        const __pad = (n) => String(Math.abs(n | 0)).padStart(2, '0');
        Date.prototype.getTimezoneOffset = __tzseal(function getTimezoneOffset() {{ return __offMin(this); }}, 'getTimezoneOffset');
        const __mkString = (date, withDate, withTime) => {{
            const t = date.getTime();
            if (!isFinite(t)) return 'Invalid Date';
            const off = __offMin(date);
            const w = new __OrigDate(t - off * 60000); // local wall clock, read via UTC getters
            const datePart = __WD[w.getUTCDay()] + ' ' + __MO[w.getUTCMonth()] + ' ' + __pad(w.getUTCDate()) + ' ' + w.getUTCFullYear();
            const sign = off <= 0 ? '+' : '-';
            const gmt = 'GMT' + sign + __pad(Math.floor(Math.abs(off) / 60)) + __pad(Math.abs(off) % 60);
            const name = __zoneLong(date);
            const timePart = __pad(w.getUTCHours()) + ':' + __pad(w.getUTCMinutes()) + ':' + __pad(w.getUTCSeconds())
                + ' ' + gmt + (name ? ' (' + name + ')' : '');
            if (withDate && withTime) return datePart + ' ' + timePart;
            if (withDate) return datePart;
            return timePart;
        }};
        Date.prototype.toString = __tzseal(function toString() {{ return __mkString(this, true, true); }}, 'toString');
        Date.prototype.toDateString = __tzseal(function toDateString() {{ return __mkString(this, true, false); }}, 'toDateString');
        Date.prototype.toTimeString = __tzseal(function toTimeString() {{ return __mkString(this, false, true); }}, 'toTimeString');
        // Date.toLocale*: default BOTH the persona locale and zone when unspecified.
        const __dateLocaleWrap = (name) => {{
            const orig = Date.prototype[name];
            if (typeof orig !== 'function') return;
            Date.prototype[name] = __tzseal(function () {{
                const args = Array.prototype.slice.call(arguments);
                if (args[0] === undefined) args[0] = __LOCALE;
                const opts = Object.assign({{}}, args[1] || {{}});
                if (!opts.timeZone) opts.timeZone = __TZ;
                return orig.call(this, args[0], opts);
            }}, name);
        }};
        __dateLocaleWrap('toLocaleString');
        __dateLocaleWrap('toLocaleDateString');
        __dateLocaleWrap('toLocaleTimeString');
        // Number.toLocaleString + String.localeCompare default the persona locale.
        try {{
            const __numOrig = Number.prototype.toLocaleString;
            Number.prototype.toLocaleString = __tzseal(function toLocaleString() {{
                const args = Array.prototype.slice.call(arguments);
                if (args[0] === undefined) args[0] = __LOCALE;
                return __numOrig.apply(this, args);
            }}, 'toLocaleString');
        }} catch (_) {{}}
        try {{
            const __scOrig = String.prototype.localeCompare;
            String.prototype.localeCompare = __tzseal(function localeCompare() {{
                const args = Array.prototype.slice.call(arguments);
                if (args[1] === undefined) args[1] = __LOCALE;
                return __scOrig.apply(this, args);
            }}, 'localeCompare');
        }} catch (_) {{}}
        // Intl.DateTimeFormat: inject the persona LOCALE and ZONE into the REAL
        // instance so format() AND resolvedOptions() genuinely use them.
        const __DTF = function DateTimeFormat() {{
            const args = Array.prototype.slice.call(arguments);
            if (args.length === 0 || args[0] === undefined) args[0] = __LOCALE;
            if (!(args[1] && args[1].timeZone)) {{
                args[1] = Object.assign({{}}, args[1] || {{}});
                args[1].timeZone = __TZ;
            }}
            return Reflect.construct(__OrigDTF, args, new.target || __DTF);
        }};
        __DTF.prototype = __OrigDTF.prototype;
        try {{
            __DTF.supportedLocalesOf = __tzseal(function supportedLocalesOf() {{
                return __OrigDTF.supportedLocalesOf.apply(__OrigDTF, arguments);
            }}, 'supportedLocalesOf');
        }} catch (_) {{}}
        Intl.DateTimeFormat = __tzseal(__DTF, 'DateTimeFormat');
        // Repoint the (shared) prototype's `constructor` at the wrapper so
        // `new Intl.DateTimeFormat().constructor === Intl.DateTimeFormat` and
        // `Intl.DateTimeFormat.prototype.constructor === Intl.DateTimeFormat` hold,
        // exactly as in a real engine. Without this the constructor still pointed
        // at the captured original, a trivial one-line tampering tell. The native
        // descriptor (writable, non-enumerable, configurable) is preserved.
        try {{ Object.defineProperty(__DTF.prototype, 'constructor', {{ value: __DTF, writable: true, enumerable: false, configurable: true }}); }} catch (_) {{}}
        // The other Intl constructors: default the persona LOCALE when unspecified.
        const __wrapIntlLocale = (ctorName) => {{
            const Orig = Intl[ctorName];
            if (typeof Orig !== 'function') return;
            const Wrapped = function () {{
                const args = Array.prototype.slice.call(arguments);
                if (args.length === 0 || args[0] === undefined) args[0] = __LOCALE;
                return Reflect.construct(Orig, args, new.target || Wrapped);
            }};
            Wrapped.prototype = Orig.prototype;
            try {{
                Wrapped.supportedLocalesOf = __tzseal(function supportedLocalesOf() {{
                    return Orig.supportedLocalesOf.apply(Orig, arguments);
                }}, 'supportedLocalesOf');
            }} catch (_) {{}}
            Intl[ctorName] = __tzseal(Wrapped, ctorName);
            // Keep `Intl[ctorName].prototype.constructor === Intl[ctorName]` (real-
            // engine invariant); otherwise it still points at the captured original
            //: a trivial constructor-identity tell.
            try {{ Object.defineProperty(Wrapped.prototype, 'constructor', {{ value: Wrapped, writable: true, enumerable: false, configurable: true }}); }} catch (_) {{}}
        }};
        ['NumberFormat', 'Collator', 'RelativeTimeFormat', 'PluralRules', 'ListFormat'].forEach(__wrapIntlLocale);
    }} catch (_) {{}}
"#,
        locale = locale,
        tz = tz,
    )
}

#[cfg(test)]
#[path = "intl_js/tests.rs"]
mod tests;
