//! Small byte-level helpers shared by the sign/verify paths.

/// Find the first occurrence of `needle` in `haystack`, returning its start index.
pub(crate) fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Lowercase hex-encode `bytes`.
pub(crate) fn hex_encode(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    out
}

/// Decode an ASCII hex string into bytes. Ignores nothing; expects even length.
pub(crate) fn hex_decode(hex: &[u8]) -> Option<Vec<u8>> {
    #[allow(clippy::manual_is_multiple_of)] // `is_multiple_of` needs Rust 1.87; MSRV is 1.83
    if hex.len() % 2 != 0 {
        return None;
    }
    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.chunks_exact(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}

/// Given a buffer starting with a DER element, return the total length
/// (header + content) of the outermost element. Used to slice the real CMS
/// blob out of a zero-padded `/Contents` placeholder.
pub(crate) fn der_total_len(b: &[u8]) -> Option<usize> {
    if b.len() < 2 {
        return None;
    }
    let len_byte = b[1];
    if len_byte < 0x80 {
        Some(2 + len_byte as usize)
    } else {
        let n = (len_byte & 0x7f) as usize;
        // A length-of-length wider than usize cannot describe anything we can
        // hold; reject it instead of shifting bits away (checked arithmetic
        // throughout so a crafted /Contents cannot panic the verifier).
        if n == 0 || n > std::mem::size_of::<usize>() || b.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = len.checked_shl(8)? | b[2 + i] as usize;
        }
        len.checked_add(2 + n)
    }
}

#[cfg(test)]
mod tests {
    use super::der_total_len;

    #[test]
    fn der_total_len_rejects_overflowing_lengths() {
        assert_eq!(der_total_len(&[0x30, 0x05]), Some(7));
        assert_eq!(der_total_len(&[0x30, 0x82, 0x01, 0x00]), Some(4 + 256));
        // 8 length bytes of 0xFF: 2 + 8 + usize::MAX overflows.
        let mut b = vec![0x30, 0x88];
        b.extend_from_slice(&[0xFF; 8]);
        assert_eq!(der_total_len(&b), None);
        // Length-of-length wider than usize.
        let mut b = vec![0x30, 0x89];
        b.extend_from_slice(&[0x01; 9]);
        assert_eq!(der_total_len(&b), None);
    }
}
