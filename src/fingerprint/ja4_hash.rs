//! Shared SHA-256 helper for the JA4 fingerprint family.
//!
//! Both `fingerprint::ja3` (JA4 client hash) and `fingerprint::ja4_family`
//! (JA4S/JA4X hashes) need the same FoxIO-spec truncation: SHA-256 of a
//! canonical string, rendered as the first six bytes (twelve hex chars).
//! This tiny module keeps that one primitive in one place.

use sha2::{Digest, Sha256};

/// SHA-256 of `input`, truncated to the first six bytes as twelve hex chars.
#[must_use]
pub(crate) fn sha256_first_12(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_empty_hash() {
        // SHA256("") truncated.
        assert_eq!(sha256_first_12(""), "e3b0c44298fc");
    }

    #[test]
    fn known_abc_hash() {
        // SHA256("abc") = ba7816bf8f01cfea... -> first 6 bytes.
        assert_eq!(sha256_first_12("abc"), "ba7816bf8f01");
    }
}
