//! Compatibility re-export for the canonical pacing crate.
//!
//! The pure timing implementation lives below `stealth` so transport and
//! scanner crates can consume it without depending on higher-level stealth
//! HTTP/TLS re-exports.

pub use guise_pacing::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn reexports_retry_after_parser() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        assert_eq!(parse_retry_after("5", now), Some(Duration::from_secs(5)));
    }

    #[test]
    fn retry_after_http_date_parses_rfc7231() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // RFC 7231 date format
        let date = "Wed, 21 Oct 2026 07:28:00 GMT";
        let result = parse_retry_after(date, now);
        assert!(result.is_some());
        // The result should be a positive duration (future date)
        assert!(result.unwrap() > Duration::ZERO);
    }

    #[test]
    fn retry_after_empty_string_returns_none() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(parse_retry_after("", now), None);
    }

    #[test]
    fn retry_after_invalid_string_returns_none() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(parse_retry_after("not-a-number", now), None);
    }

    #[test]
    fn retry_after_zero_seconds() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(parse_retry_after("0", now), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_large_seconds_is_capped() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // Values above MAX_RETRY_AFTER_OBEYED (60s) are capped.
        assert_eq!(
            parse_retry_after("86400", now),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn retry_after_past_date_returns_zero_or_none() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let past_date = "Wed, 21 Oct 2020 07:28:00 GMT";
        let result = parse_retry_after(past_date, now);
        // A date in the past should yield None or a zero/negative duration
        assert!(result.is_none() || result.unwrap() == Duration::ZERO);
    }
}
