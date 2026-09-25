//! RFC 3161 timestamp client (for PAdES-B-T and the B-LTA document timestamp).
//!
//! Builds a `TimeStampReq` over a message imprint, POSTs it to a Time-Stamping
//! Authority, and returns the `TimeStampToken` (a CMS `ContentInfo`) to embed
//! as an unsigned attribute or in a `/DocTimeStamp`. The response is checked
//! before it is accepted: PKIStatus, the token's own CMS signature over its
//! `TSTInfo`, and that it stamps the imprint (algorithm, hash **and nonce**) we
//! asked for.
//!
//! Without the `https` feature the HTTP client is a tiny hand-rolled
//! `std::net` POST so the crate stays pure-Rust and dependency-free; only
//! `http://` endpoints are then supported. With `https`, `ureq`/`rustls`
//! handle both `http://` and `https://`.

#[cfg(not(feature = "https"))]
use std::io::{Read, Write};
#[cfg(not(feature = "https"))]
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use cms::content_info::ContentInfo;
use const_oid::db::rfc5912::ID_SHA_256;
use der::asn1::{BitString, Int, OctetString};
use der::{Any, Decode, Encode, Sequence};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;

use crate::error::Error;
use crate::Result;

/// Overall time budget for one TSA / CRL / OCSP request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Time budget for establishing the TCP (and TLS) connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest response body we are willing to read (a token is a few KB; a CRL
/// can be MBs).
const MAX_RESPONSE_BYTES: usize = 20 * 1024 * 1024;

fn tsa<E: std::fmt::Display>(e: E) -> Error {
    Error::Crypto(e.to_string())
}

#[derive(Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

#[derive(Sequence)]
struct TimeStampReq {
    version: i32,
    message_imprint: MessageImprint,
    nonce: Int,
    cert_req: bool,
}

#[derive(Sequence)]
struct PkiStatusInfo {
    status: i32,
    #[asn1(optional = "true")]
    status_string: Option<Any>,
    #[asn1(optional = "true")]
    fail_info: Option<BitString>,
}

#[derive(Sequence)]
struct TimeStampResp {
    status: PkiStatusInfo,
    #[asn1(optional = "true")]
    token: Option<ContentInfo>,
}

/// Request an RFC 3161 timestamp token over `signature` from `tsa_url`.
/// Returns the TimeStampToken `ContentInfo`, already verified to be a
/// well-formed token that binds our imprint and nonce.
pub(crate) fn request_timestamp(tsa_url: &str, signature: &[u8]) -> Result<ContentInfo> {
    let imprint = Sha256::digest(signature);
    // A fresh 64-bit nonce (RFC 3161 §2.4.1) binds the response to this request
    // so a replayed or unrelated token is rejected.
    let nonce_bytes = random_nonce();
    let req = TimeStampReq {
        version: 1,
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: ID_SHA_256,
                parameters: None,
            },
            hashed_message: OctetString::new(imprint.to_vec()).map_err(tsa)?,
        },
        nonce: Int::new(&nonce_bytes).map_err(tsa)?,
        cert_req: true,
    };

    let body = req.to_der().map_err(tsa)?;
    let resp = http_post(tsa_url, "application/timestamp-query", &body)?;

    let parsed = TimeStampResp::from_der(&resp)
        .map_err(|e| Error::Crypto(format!("malformed TSA response: {e}")))?;
    // PKIStatus: 0 = granted, 1 = grantedWithMods.
    if !matches!(parsed.status.status, 0 | 1) {
        return Err(Error::Crypto(format!(
            "TSA rejected the request (PKIStatus {}{}{})",
            parsed.status.status,
            parsed
                .status
                .fail_info
                .as_ref()
                .and_then(|b| b.as_bytes())
                .map(|b| format!(", failInfo {b:02x?}"))
                .unwrap_or_default(),
            parsed
                .status
                .status_string
                .as_ref()
                .map(|s| format!(", {}", String::from_utf8_lossy(s.value())))
                .unwrap_or_default(),
        )));
    }
    let token = parsed
        .token
        .ok_or_else(|| Error::Crypto("TSA response carried no timestamp token".into()))?;

    // Verify the token before embedding it: its TSA signature over the TSTInfo
    // must be valid, and it must stamp *our* imprint (same hash algorithm) with
    // *our* nonce — not something else.
    let token_der = token.to_der().map_err(tsa)?;
    let ts = crate::crypto::verify_timestamp_token(&token_der)
        .map_err(|e| Error::Crypto(format!("TSA returned an invalid token: {e}")))?;
    if ts.imprint_alg != ID_SHA_256 || ts.imprint.as_slice() != imprint.as_slice() {
        return Err(Error::Crypto(
            "TSA response imprint does not match the request".into(),
        ));
    }
    let want_nonce = Int::new(&nonce_bytes).map_err(tsa)?;
    if ts.nonce.as_deref() != Some(want_nonce.as_bytes()) {
        return Err(Error::Crypto(
            "TSA response nonce does not match the request".into(),
        ));
    }
    Ok(token)
}

/// 8 random bytes, forced positive as a DER INTEGER (top bit clear, non-zero).
fn random_nonce() -> [u8; 8] {
    use rand::RngCore;
    let mut n = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut n);
    n[0] &= 0x7f;
    n[0] |= 0x40;
    n
}

/// POST `body` to `url`. Returns the response body.
pub(crate) fn http_post(url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>> {
    fetch("POST", url, Some(content_type), body)
}

/// GET `url` (used to fetch CRLs for the DSS). Returns the response body.
pub(crate) fn http_get(url: &str) -> Result<Vec<u8>> {
    fetch("GET", url, None, &[])
}

/// Dispatch to the TLS-capable client when the `https` feature is on, otherwise
/// the dependency-free plain-HTTP client.
#[cfg(feature = "https")]
fn fetch(method: &str, url: &str, content_type: Option<&str>, body: &[u8]) -> Result<Vec<u8>> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .max_redirects(5)
        .http_status_as_error(true)
        .build()
        .new_agent();
    let mut resp = if method == "POST" {
        let mut req = agent.post(url);
        if let Some(ct) = content_type {
            req = req.header("Content-Type", ct);
        }
        req.send(body).map_err(tsa)?
    } else {
        agent.get(url).call().map_err(tsa)?
    };
    resp.body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES as u64)
        .read_to_vec()
        .map_err(tsa)
}

#[cfg(not(feature = "https"))]
fn fetch(method: &str, url: &str, content_type: Option<&str>, body: &[u8]) -> Result<Vec<u8>> {
    http_request_plain(method, url, content_type, body)
}

/// Minimal HTTP/1.1 request over plain TCP (no TLS). Returns the response body.
/// Bounded in time (connect + overall deadline) and size.
#[cfg(not(feature = "https"))]
fn http_request_plain(
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Vec<u8>> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| Error::Crypto("URL must start with http:// (enable the `https` feature for https://)".into()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // host[:port], with IPv6 literals in brackets.
    let (host, port) = if let Some(h) = authority.strip_prefix('[') {
        let (h, tail) = h
            .split_once(']')
            .ok_or_else(|| Error::Crypto("malformed IPv6 authority".into()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(tsa)?,
            None => 80,
        };
        (h, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(tsa)?),
            None => (authority, 80),
        }
    };
    let host_header = if port == 80 {
        host.to_string()
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::Crypto(format!("cannot resolve {host}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

    let mut header = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nUser-Agent: pdf_signer\r\n"
    );
    if let Some(ct) = content_type {
        header.push_str(&format!("Content-Type: {ct}\r\nContent-Length: {}\r\n", body.len()));
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush().ok();

    // Read with a size cap and an overall deadline (a server dripping bytes
    // must not hold us past REQUEST_TIMEOUT).
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if std::time::Instant::now() > deadline {
            return Err(Error::Crypto("HTTP request timed out".into()));
        }
        let n = match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e.into()),
        };
        if raw.len() + n > MAX_RESPONSE_BYTES {
            return Err(Error::Crypto("HTTP response too large".into()));
        }
        raw.extend_from_slice(&chunk[..n]);
    }

    let idx = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::Crypto("malformed HTTP response".into()))?;
    let head = &raw[..idx];
    let body_bytes = raw[idx + 4..].to_vec();

    let status_line = String::from_utf8_lossy(head.split(|&b| b == b'\n').next().unwrap_or(&[]));
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Crypto(format!("malformed HTTP status line: {}", status_line.trim())))?;
    if status != 200 {
        return Err(Error::Crypto(format!("HTTP error: {}", status_line.trim())));
    }

    if String::from_utf8_lossy(head)
        .to_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return dechunk(&body_bytes);
    }
    Ok(body_bytes)
}

/// Decode HTTP/1.1 chunked transfer-encoding (checked arithmetic, framing
/// validated).
#[cfg(not(feature = "https"))]
fn dechunk(data: &[u8]) -> Result<Vec<u8>> {
    let bad = |what: &str| Error::Crypto(format!("bad chunked encoding: {what}"));
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let line_end = i + data[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| bad("missing chunk header"))?;
        let size_field = String::from_utf8_lossy(&data[i..line_end]);
        let size = usize::from_str_radix(size_field.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| bad("chunk size"))?;
        i = line_end + 2;
        if size == 0 {
            break;
        }
        let end = i.checked_add(size).ok_or_else(|| bad("chunk size overflow"))?;
        if end + 2 > data.len() {
            return Err(bad("truncated chunk"));
        }
        if &data[end..end + 2] != b"\r\n" {
            return Err(bad("chunk not CRLF-terminated"));
        }
        out.extend_from_slice(&data[i..end]);
        if out.len() > MAX_RESPONSE_BYTES {
            return Err(Error::Crypto("HTTP response too large".into()));
        }
        i = end + 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "https"))]
    #[test]
    fn dechunk_validates_framing() {
        use super::dechunk;
        assert_eq!(dechunk(b"3\r\nabc\r\n0\r\n\r\n").unwrap(), b"abc");
        assert!(dechunk(b"3\r\nabcXX0\r\n\r\n").is_err(), "missing CRLF after chunk");
        assert!(dechunk(b"ffffffffffffffff\r\nabc").is_err(), "oversized chunk");
    }

    #[test]
    fn nonce_is_a_positive_der_integer() {
        let n = super::random_nonce();
        assert!(n[0] & 0x80 == 0 && n[0] != 0);
    }
}
