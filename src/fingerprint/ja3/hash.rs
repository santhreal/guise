//! Hand-rolled hashing primitives backing JA3 (MD5) and JA4 (SHA-256) digests.
//!
//! These are pure transforms over byte strings. `md5_string` implements RFC 1321
//! directly so JA3 has no external MD5 dependency; `sha256_first_12` wraps the
//! `sha2` crate and renders the first six digest bytes as twelve hex chars for
//! JA4's truncated cipher and extension hashes.

pub(crate) fn md5_string(input: &str) -> String {
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let bytes = input.as_bytes();
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bit_len = (bytes.len() as u64) * 8;
    padded.extend_from_slice(&bit_len.to_le_bytes());
    for chunk in padded.chunks_exact(64) {
        md5_round(&mut state, chunk);
    }
    let mut out = String::with_capacity(32);
    for word in state {
        for byte in word.to_le_bytes() {
            out.push_str(&format!("{byte:02x}"));
        }
    }
    out
}

fn md5_round(state: &mut [u32; 4], block: &[u8]) {
    debug_assert_eq!(block.len(), 64);
    let mut m = [0u32; 16];
    for (index, chunk) in block.chunks_exact(4).enumerate() {
        m[index] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    let [mut a, mut b, mut c, mut d] = *state;

    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    for index in 0..64usize {
        let (mut f, g) = if index < 16 {
            ((b & c) | (!b & d), index)
        } else if index < 32 {
            ((d & b) | (!d & c), (5 * index + 1) % 16)
        } else if index < 48 {
            (b ^ c ^ d, (3 * index + 5) % 16)
        } else {
            (c ^ (b | !d), (7 * index) % 16)
        };
        f = f.wrapping_add(a).wrapping_add(K[index]).wrapping_add(m[g]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(f.rotate_left(S[index]));
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

pub(crate) fn sha256_first_12(input: &str) -> String {
    crate::fingerprint::ja4_hash::sha256_first_12(input)
}
