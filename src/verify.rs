//! Verification path: re-derive the signed byte range and validate the CMS.

use std::collections::BTreeSet;
use std::path::Path;

use std::time::SystemTime;

use der::Decode;
use lopdf::{Dictionary, Document, Object, ObjectId};
use x509_cert::crl::CertificateList;
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, OcspResponse};

use crate::crypto::{
    cms_verify, signer_certificate_and_pool, verify_doc_timestamp, verify_embedded_timestamp,
    VerifiedTimestamp,
};
use crate::error::Error;
use crate::trust::{verify_chain, LeafPurpose, TrustStore};
use crate::util::{der_total_len, find_sub, hex_decode};
use crate::Result;

/// Validate a certificate path directly (decoupled from PDF signing): does
/// `leaf_der` chain to a trusted root in `roots`, using `pool_ders` as candidate
/// intermediates and `crl_ders` for revocation, at time `at`? Exposed mainly for
/// conformance testing (e.g. NIST PKITS), so no purpose-specific leaf key-usage
/// check is applied.
pub fn verify_certificate_chain(
    leaf_der: &[u8],
    pool_ders: &[Vec<u8>],
    crl_ders: &[Vec<u8>],
    roots: &TrustStore,
    at: SystemTime,
) -> bool {
    let Ok(leaf) = Certificate::from_der(leaf_der) else {
        return false;
    };
    let pool: Vec<Certificate> = pool_ders
        .iter()
        .filter_map(|d| Certificate::from_der(d).ok())
        .collect();
    let crls = parse_crls(crl_ders);
    verify_chain(&leaf, &pool, roots, &crls, &[], at, LeafPurpose::Any).trusted
}

/// Parse CRL DER blobs, silently dropping any that fail to decode.
fn parse_crls(ders: &[Vec<u8>]) -> Vec<CertificateList> {
    ders.iter()
        .filter_map(|d| CertificateList::from_der(d).ok())
        .collect()
}

/// Parse OCSP response DER blobs into their inner `BasicOCSPResponse`.
fn parse_ocsps(ders: &[Vec<u8>]) -> Vec<BasicOcspResponse> {
    ders.iter()
        .filter_map(|d| {
            let rb = OcspResponse::from_der(d).ok()?.response_bytes?;
            BasicOcspResponse::from_der(rb.response.as_bytes()).ok()
        })
        .collect()
}

/// Outcome of verifying a single signature or document timestamp.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedSignature {
    /// Whether the CMS signature (or RFC 3161 token) is cryptographically valid
    /// over the byte range **and** the `/ByteRange` itself is well-formed.
    pub valid: bool,
    /// `true` for a document timestamp (`/SubFilter /ETSI.RFC3161`), `false`
    /// for a signature.
    pub is_timestamp: bool,
    /// The four `/ByteRange` integers `[start1, len1, start2, len2]`.
    pub byte_range: [i64; 4],
    /// Number of bytes covered by the signature.
    pub signed_len: usize,
    /// Whether the byte range covers the whole file except the signature hole.
    pub covers_whole_document: bool,
    /// Signer certificate subject DN (the TSA's, for a document timestamp),
    /// when the signature could be parsed.
    pub signer: Option<String>,
    /// Whether the signer certificate (the TSA's, for a document timestamp)
    /// chains to a trusted root. `None` when no trust store was supplied.
    pub chain_trusted: Option<bool>,
    /// The authenticated time the signer chain was judged at — the `genTime`
    /// of a trusted RFC 3161 timestamp — or `None` when the chain was judged at
    /// the current time (no timestamp, or its TSA is not trusted).
    pub trusted_time: Option<SystemTime>,
    /// Human-readable detail (error message when invalid).
    pub detail: String,
}

/// Report over all signatures and document timestamps found, in file order.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignatureReport {
    pub signatures: Vec<VerifiedSignature>,
    /// Whether the document as a whole is what was signed: the last valid
    /// signature or document timestamp covers the entire file, or every byte
    /// after it is an incremental update that adds nothing but a Document
    /// Security Store (`/DSS`, the PAdES-B-LT validation material). Any other
    /// unsigned change after the last signature — replaced page content, added
    /// annotations, form fills — makes this `false` even though the signature
    /// over the *original* bytes still verifies.
    pub document_intact: bool,
}

impl SignatureReport {
    /// True if at least one signature was found, every signature and document
    /// timestamp is cryptographically valid, **and** the document was not
    /// modified after the last one ([`document_intact`](Self::document_intact)).
    /// This says **nothing** about trust — a self-signed or untrusted
    /// signature can still be `all_valid`. When a trust store was supplied,
    /// use [`all_trusted`](Self::all_trusted).
    pub fn all_valid(&self) -> bool {
        !self.signatures.is_empty()
            && self.signatures.iter().all(|s| s.valid)
            && self.document_intact
    }

    /// True if [`all_valid`](Self::all_valid) **and** every signature and
    /// document timestamp chains to a trusted root (`chain_trusted ==
    /// Some(true)`). Always `false` when no trust store was supplied.
    pub fn all_trusted(&self) -> bool {
        self.all_valid()
            && self
                .signatures
                .iter()
                .all(|s| s.chain_trusted == Some(true))
    }

    /// See the [`document_intact`](Self::document_intact) field.
    pub fn document_intact(&self) -> bool {
        self.document_intact
    }
}

/// Verify the signatures of a PDF file.
pub fn verify_pdf_file(path: impl AsRef<Path>) -> Result<SignatureReport> {
    let pdf = std::fs::read(path)?;
    verify_pdf_bytes(&pdf)
}

/// Verify all signatures of an in-memory PDF (one per `/ByteRange`).
pub fn verify_pdf_bytes(pdf: &[u8]) -> Result<SignatureReport> {
    verify_pdf_bytes_with_roots(pdf, &TrustStore::new())
}

/// Verify a PDF file, additionally validating each signer certificate chain
/// against `roots` (e.g. the ICP-Brasil roots).
pub fn verify_pdf_file_with_roots(
    path: impl AsRef<Path>,
    roots: &TrustStore,
) -> Result<SignatureReport> {
    let pdf = std::fs::read(path)?;
    verify_pdf_bytes_with_roots(&pdf, roots)
}

/// A signature located in the document: its `/ByteRange`, the raw `/Contents`
/// bytes (hex-decoded, including any zero padding), and whether it is a document
/// timestamp (`/SubFilter /ETSI.RFC3161`).
struct SigLoc {
    byte_range: [i64; 4],
    contents: Vec<u8>,
    is_timestamp: bool,
}

/// The revocation material a document carries in its `/DSS`.
struct DssMaterial {
    crls: Vec<CertificateList>,
    ocsps: Vec<BasicOcspResponse>,
}

/// Verify an in-memory PDF, validating signer chains against `roots`.
///
/// Document timestamps are processed first (last one first): each TSA is
/// validated at the current time or, failing that, at the `genTime` of a
/// later, already-trusted document timestamp — the PAdES-B-LTA chain of
/// archival timestamps. The earliest trusted `genTime` then also serves as the
/// fallback validation time for the TSAs of the signatures' own timestamps,
/// so a B-LTA document stays verifiable after its TSA certificates expire.
pub fn verify_pdf_bytes_with_roots(pdf: &[u8], roots: &TrustStore) -> Result<SignatureReport> {
    let locs = collect_signatures(pdf);
    let dss = DssMaterial {
        crls: parse_crls(&crate::dss::extract_dss_crls(pdf)),
        ocsps: parse_ocsps(&crate::dss::extract_dss_ocsps(pdf)),
    };

    // Pass 1: document timestamps, latest first, chaining trusted genTimes.
    let mut results: Vec<Option<VerifiedSignature>> = vec![None; locs.len()];
    let mut anchor: Option<SystemTime> = None;
    for (i, loc) in locs.iter().enumerate().rev() {
        if loc.is_timestamp {
            let v = verify_doc_ts(pdf, loc, roots, &dss, anchor);
            if v.chain_trusted == Some(true) {
                if let Some(t) = v.trusted_time {
                    anchor = Some(anchor.map_or(t, |a| a.min(t)));
                }
            }
            results[i] = Some(v);
        }
    }
    // Pass 2: signatures.
    for (i, loc) in locs.iter().enumerate() {
        if !loc.is_timestamp {
            results[i] = Some(verify_signature(pdf, loc, roots, &dss, anchor));
        }
    }
    let signatures: Vec<VerifiedSignature> = results.into_iter().flatten().collect();
    let document_intact = document_intact(pdf, &signatures);
    Ok(SignatureReport {
        signatures,
        document_intact,
    })
}

/// Locate every signature by document **structure** — the signature dictionaries
/// (`/ByteRange` + `/Contents`) in the parsed object set — rather than by
/// scanning the raw bytes for `/ByteRange`, which could match a string, stream
/// or comment. Reads `/ByteRange` and `/SubFilter` from the dictionary, so it
/// does not depend on key order. Falls back to a byte scan only if the document
/// cannot be parsed at all.
fn collect_signatures(pdf: &[u8]) -> Vec<SigLoc> {
    // Only fall back to scanning when the document cannot be parsed at all. A
    // document that parses but has no signature dictionaries genuinely has no
    // signatures — a `/ByteRange` found loose in a stream or string is not one.
    let Ok(doc) = Document::load_mem(pdf) else {
        return collect_signatures_by_scan(pdf);
    };
    let mut sigs: Vec<SigLoc> = doc
        .objects
        .values()
        .filter_map(|obj| obj.as_dict().ok())
        .filter_map(signature_from_dict)
        .collect();
    // Report in file order: an earlier signature's `/Contents` hex string (which
    // begins at `s1 + l1`) sits at a lower offset than a later one.
    sigs.sort_by_key(|s| s.byte_range[0].saturating_add(s.byte_range[1]));
    sigs
}

/// Recognize a signature dictionary and read the fields we need, regardless of
/// key order. A signature dictionary carries both a `/ByteRange` array and a
/// `/Contents` string.
fn signature_from_dict(dict: &Dictionary) -> Option<SigLoc> {
    let contents = dict.get(b"Contents").ok()?.as_str().ok()?.to_vec();
    let arr = dict.get(b"ByteRange").ok()?.as_array().ok()?;
    if arr.len() != 4 {
        return None;
    }
    let mut byte_range = [0i64; 4];
    for (slot, v) in byte_range.iter_mut().zip(arr) {
        *slot = v.as_i64().ok()?;
    }
    let is_timestamp = dict.get(b"SubFilter").ok().and_then(|o| o.as_name().ok())
        == Some(b"ETSI.RFC3161".as_ref());
    Some(SigLoc {
        byte_range,
        contents,
        is_timestamp,
    })
}

/// Fallback enumeration for documents that fail to parse: scan the raw bytes for
/// each `/ByteRange` (the historical behavior).
fn collect_signatures_by_scan(pdf: &[u8]) -> Vec<SigLoc> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = find_sub(&pdf[from..], b"/ByteRange") {
        let br = from + rel;
        from = br + b"/ByteRange".len();
        if let (Ok(byte_range), Some(contents)) =
            (parse_byte_range(&pdf[br..]), scan_contents(pdf, br))
        {
            let is_timestamp = subfilter_before(pdf, br).as_deref() == Some(b"ETSI.RFC3161");
            out.push(SigLoc {
                byte_range,
                contents,
                is_timestamp,
            });
        }
    }
    out
}

/// Scan for the `/Contents <...>` hex string following `/ByteRange` at `br` and
/// decode it (fallback path only).
fn scan_contents(pdf: &[u8], br: usize) -> Option<Vec<u8>> {
    let from = br + find_sub(&pdf[br..], b"/Contents")?;
    let lt = from + find_sub(&pdf[from..], b"<")?;
    let gt = lt + find_sub(&pdf[lt..], b">")?;
    hex_decode(&pdf[lt + 1..gt])
}

/// The signed bytes and coverage facts derived from a well-formed `/ByteRange`.
struct Ranged {
    signed: Vec<u8>,
    signed_len: usize,
    covers_whole_document: bool,
}

/// Validate a `/ByteRange` structurally (non-negative, in bounds, ordered and
/// non-overlapping) and reassemble the signed bytes. `Err` carries the reason
/// the range is malformed.
fn ranged(pdf: &[u8], sig: &SigLoc) -> std::result::Result<Ranged, String> {
    let to_usize = |v: i64| usize::try_from(v).map_err(|_| "negative ByteRange value".to_string());
    let s1 = to_usize(sig.byte_range[0])?;
    let l1 = to_usize(sig.byte_range[1])?;
    let s2 = to_usize(sig.byte_range[2])?;
    let l2 = to_usize(sig.byte_range[3])?;
    let e1 = s1.checked_add(l1).ok_or("ByteRange overflow")?;
    let e2 = s2.checked_add(l2).ok_or("ByteRange overflow")?;
    if e1 > pdf.len() || e2 > pdf.len() {
        return Err("ByteRange out of bounds".into());
    }
    if e1 > s2 {
        return Err("ByteRange segments overlap or are out of order".into());
    }
    let mut signed = Vec::with_capacity(l1 + l2);
    signed.extend_from_slice(&pdf[s1..e1]);
    signed.extend_from_slice(&pdf[s2..e2]);
    // "Covers the whole document" requires spanning byte 0 to EOF *and* that the
    // only excluded bytes — the ByteRange gap `[s1+l1, s2)` — are exactly the
    // `/Contents <...>` hex string. Otherwise a ByteRange could leave arbitrary
    // unsigned bytes in the gap and still claim full coverage.
    let covers_whole_document =
        s1 == 0 && e2 == pdf.len() && gap_is_contents(pdf, e1, s2, &sig.contents);
    Ok(Ranged {
        signed,
        signed_len: l1 + l2,
        covers_whole_document,
    })
}

/// A report entry for a signature whose byte range or CMS is unusable.
fn malformed(sig: &SigLoc, detail: String) -> VerifiedSignature {
    VerifiedSignature {
        valid: false,
        is_timestamp: sig.is_timestamp,
        byte_range: sig.byte_range,
        signed_len: 0,
        covers_whole_document: false,
        signer: None,
        chain_trusted: None,
        trusted_time: None,
        detail,
    }
}

/// Validate the TSA of a verified token against `roots` at the current time
/// or, failing that, at `anchor` (a later trusted archival timestamp).
/// Returns the trust verdict and the time it was reached at.
fn tsa_trusted(
    ts: &VerifiedTimestamp,
    roots: &TrustStore,
    dss: &DssMaterial,
    anchor: Option<SystemTime>,
) -> (bool, String) {
    let now = verify_chain(
        &ts.tsa_leaf,
        &ts.tsa_pool,
        roots,
        &dss.crls,
        &dss.ocsps,
        SystemTime::now(),
        LeafPurpose::TimeStamping,
    );
    if now.trusted {
        return (true, now.detail);
    }
    if let Some(at) = anchor {
        let then = verify_chain(
            &ts.tsa_leaf,
            &ts.tsa_pool,
            roots,
            &dss.crls,
            &dss.ocsps,
            at,
            LeafPurpose::TimeStamping,
        );
        if then.trusted {
            return (true, format!("{} (at a later archival timestamp)", then.detail));
        }
    }
    (false, now.detail)
}

/// Verify one document timestamp entry.
fn verify_doc_ts(
    pdf: &[u8],
    sig: &SigLoc,
    roots: &TrustStore,
    dss: &DssMaterial,
    anchor: Option<SystemTime>,
) -> VerifiedSignature {
    let r = match ranged(pdf, sig) {
        Ok(r) => r,
        Err(e) => return malformed(sig, e),
    };
    let der = match cms_from_contents(&sig.contents) {
        Ok(d) => d,
        Err(e) => return malformed(sig, e.to_string()),
    };
    let (valid, ts, mut detail) = match verify_doc_timestamp(&der, &r.signed) {
        Ok(ts) => (true, Some(ts), "valid document timestamp (RFC 3161)".to_string()),
        Err(e) => (false, None, e.to_string()),
    };
    let signer = ts
        .as_ref()
        .map(|t| t.tsa_leaf.tbs_certificate.subject.to_string());
    let mut chain_trusted = None;
    let mut trusted_time = None;
    if !roots.is_empty() {
        match &ts {
            Some(ts) => {
                let (trusted, d) = tsa_trusted(ts, roots, dss, anchor);
                chain_trusted = Some(trusted);
                if trusted {
                    trusted_time = Some(ts.gen_time);
                }
                detail = format!("{detail}; TSA chain: {d}");
            }
            None => chain_trusted = Some(false),
        }
    }
    VerifiedSignature {
        valid,
        is_timestamp: true,
        byte_range: sig.byte_range,
        signed_len: r.signed_len,
        covers_whole_document: r.covers_whole_document,
        signer,
        chain_trusted,
        trusted_time,
        detail,
    }
}

/// Verify one signature entry.
fn verify_signature(
    pdf: &[u8],
    sig: &SigLoc,
    roots: &TrustStore,
    dss: &DssMaterial,
    anchor: Option<SystemTime>,
) -> VerifiedSignature {
    let r = match ranged(pdf, sig) {
        Ok(r) => r,
        Err(e) => return malformed(sig, e),
    };
    // The CMS comes from the structurally-parsed `/Contents`, not from the bytes
    // the ByteRange happens to point at.
    let der = match cms_from_contents(&sig.contents) {
        Ok(d) => d,
        Err(e) => return malformed(sig, e.to_string()),
    };
    let (valid, signer, mut detail) = match cms_verify(&der, &r.signed) {
        Ok(v) => (
            true,
            Some(v.signer_subject.clone()),
            format!("valid CMS signature; signer: {}", v.signer_subject),
        ),
        Err(e) => (false, None, format!("{e}")),
    };

    // Chain validation against the trust store.
    let mut chain_trusted = None;
    let mut trusted_time = None;
    if !roots.is_empty() {
        if let Ok((leaf, pool)) = signer_certificate_and_pool(&der) {
            // PAdES: judge the chain at signing time so a signature stays valid
            // after the certificate expires — but only when that time comes from
            // a trustworthy source: the `genTime` of an RFC 3161 token that
            // verifies AND whose TSA chains to a trusted root as a TSA;
            // otherwise we fall back to "now". The signer-asserted
            // `signingTime` / `/M` is never used (it would let an expired or
            // revoked certificate backdate itself past expiry/revocation).
            let (at, ts_detail) = match trusted_time_of(&der, roots, dss, anchor) {
                Ok(t) => (t, "trusted timestamp".to_string()),
                Err(why) => (SystemTime::now(), format!("no trusted timestamp ({why}); at now")),
            };
            let result = verify_chain(
                &leaf,
                &pool,
                roots,
                &dss.crls,
                &dss.ocsps,
                at,
                LeafPurpose::DocumentSigning,
            );
            chain_trusted = Some(result.trusted);
            if result.trusted && ts_detail == "trusted timestamp" {
                trusted_time = Some(at);
            }
            detail = format!("{detail}; chain: {} [{ts_detail}]", result.detail);
        } else {
            chain_trusted = Some(false);
        }
    }

    VerifiedSignature {
        valid,
        is_timestamp: false,
        byte_range: sig.byte_range,
        signed_len: r.signed_len,
        covers_whole_document: r.covers_whole_document,
        signer,
        chain_trusted,
        trusted_time,
        detail,
    }
}

/// The reference instant for validating the signer chain: the `genTime` of the
/// signature's embedded RFC 3161 timestamp, but only when that token verifies
/// cryptographically *and* the TSA's own certificate chains to a trusted root
/// with the time-stamping purpose (at the current time, or at a later trusted
/// archival timestamp `anchor`). `Err` explains why no such time exists, so the
/// caller validates at the current time.
fn trusted_time_of(
    der: &[u8],
    roots: &TrustStore,
    dss: &DssMaterial,
    anchor: Option<SystemTime>,
) -> std::result::Result<SystemTime, String> {
    let ts = verify_embedded_timestamp(der).map_err(|e| e.to_string())?;
    // The TSA must itself be trusted, else a self-issued TSA could assert any
    // genTime to dodge expiry/revocation.
    let (trusted, detail) = tsa_trusted(&ts, roots, dss, anchor);
    if trusted {
        Ok(ts.gen_time)
    } else {
        Err(format!("TSA not trusted: {detail}"))
    }
}

/// Decide [`SignatureReport::document_intact`]: the last valid entry covers
/// the whole file, or everything after it is a DSS-only incremental update.
fn document_intact(pdf: &[u8], sigs: &[VerifiedSignature]) -> bool {
    let Some(last) = sigs.last() else {
        return false;
    };
    if !last.valid {
        return false;
    }
    if last.covers_whole_document {
        return true;
    }
    let end = match (
        usize::try_from(last.byte_range[2]),
        usize::try_from(last.byte_range[3]),
    ) {
        (Ok(s2), Ok(l2)) => match s2.checked_add(l2) {
            Some(e) if e <= pdf.len() => e,
            _ => return false,
        },
        _ => return false,
    };
    // A signature that does not start at byte 0 or whose gap is not its own
    // /Contents cannot vouch for the document at all.
    if last.byte_range[0] != 0 {
        return false;
    }
    dss_only_update(pdf, end)
}

/// True if the bytes of `pdf` after `end` change nothing but the catalog's
/// `/DSS` (adding a Document Security Store and the certificate / CRL / OCSP
/// streams it references) relative to the revision that ends at `end`.
fn dss_only_update(pdf: &[u8], end: usize) -> bool {
    // The tail must be a real incremental update: the file's newest `startxref`
    // has to point into it. Trailing bytes that are not an update (garbage, a
    // comment, a truncated revision) leave the last startxref inside the signed
    // range and are not accepted.
    let base = crate::incremental::header_offset(pdf);
    match crate::incremental::last_startxref(pdf) {
        Some(off) if off + base >= end => {}
        _ => return false,
    }
    let (Ok(full), Ok(prev)) = (Document::load_mem(pdf), Document::load_mem(&pdf[..end])) else {
        return false;
    };
    let (Ok(root), Ok(prev_root)) = (
        full.trailer.get(b"Root").and_then(Object::as_reference),
        prev.trailer.get(b"Root").and_then(Object::as_reference),
    ) else {
        return false;
    };
    if root != prev_root {
        return false;
    }
    let (Ok(catalog), Ok(prev_catalog)) = (
        full.get_object(root).and_then(Object::as_dict),
        prev.get_object(root).and_then(Object::as_dict),
    ) else {
        return false;
    };
    // The catalog may differ only by its /DSS entry.
    let mut a = catalog.clone();
    let mut b = prev_catalog.clone();
    a.remove(b"DSS");
    b.remove(b"DSS");
    if a != b {
        return false;
    }
    // Objects reachable from the new /DSS may be added or replaced; nothing else.
    let mut allowed: BTreeSet<ObjectId> = BTreeSet::new();
    collect_dss_ids(&full, catalog.get(b"DSS").ok(), &mut allowed);
    for (id, obj) in &full.objects {
        if *id == root || allowed.contains(id) || is_xref_stream(obj) {
            continue;
        }
        match prev.objects.get(id) {
            Some(old) if old == obj => {}
            _ => return false,
        }
    }
    true
}

/// A cross-reference stream object (`/Type /XRef`): bookkeeping of the update
/// itself, not document content.
fn is_xref_stream(obj: &Object) -> bool {
    obj.as_stream()
        .ok()
        .and_then(|s| s.dict.get(b"Type").ok())
        .and_then(|t| t.as_name().ok())
        == Some(b"XRef".as_ref())
}

/// Collect the object ids of the `/DSS` dictionary (if indirect) and everything
/// it references, one level of nesting deep (arrays of streams, `/VRI` dicts).
fn collect_dss_ids(doc: &Document, dss: Option<&Object>, out: &mut BTreeSet<ObjectId>) {
    let Some(dss) = dss else {
        return;
    };
    let dict = match dss {
        Object::Dictionary(d) => d.clone(),
        Object::Reference(r) => {
            out.insert(*r);
            match doc.get_object(*r).and_then(Object::as_dict) {
                Ok(d) => d.clone(),
                Err(_) => return,
            }
        }
        _ => return,
    };
    for (_, v) in dict.iter() {
        collect_refs(doc, v, out, 3);
    }
}

/// Recursively collect references from `obj`, resolving referenced containers
/// up to `depth` levels.
fn collect_refs(doc: &Document, obj: &Object, out: &mut BTreeSet<ObjectId>, depth: u8) {
    match obj {
        Object::Reference(r) => {
            if out.insert(*r) && depth > 0 {
                if let Ok(inner) = doc.get_object(*r) {
                    collect_refs(doc, inner, out, depth - 1);
                }
            }
        }
        Object::Array(a) => a.iter().for_each(|o| collect_refs(doc, o, out, depth)),
        Object::Dictionary(d) => d.iter().for_each(|(_, o)| collect_refs(doc, o, out, depth)),
        _ => {}
    }
}

/// Read the `/SubFilter` name that precedes the `/ByteRange` at `br` (each
/// signature dictionary writes SubFilter before ByteRange).
fn subfilter_before(pdf: &[u8], br: usize) -> Option<Vec<u8>> {
    let hay = &pdf[..br];
    let key = b"/SubFilter";
    let pos = (0..=hay.len().saturating_sub(key.len()))
        .rev()
        .find(|&i| &hay[i..i + key.len()] == key)?;
    let mut j = pos + key.len();
    while matches!(pdf.get(j), Some(b' ' | b'\r' | b'\n' | b'\t')) {
        j += 1;
    }
    if pdf.get(j) != Some(&b'/') {
        return None;
    }
    j += 1;
    let start = j;
    while !matches!(
        pdf.get(j),
        None | Some(b' ' | b'\r' | b'\n' | b'\t' | b'/' | b'>' | b'[' | b'(')
    ) {
        j += 1;
    }
    Some(pdf[start..j].to_vec())
}

/// Parse `[a b c d]` starting at a slice beginning with `/ByteRange`.
fn parse_byte_range(s: &[u8]) -> Result<[i64; 4]> {
    let open = find_sub(s, b"[").ok_or_else(|| Error::Malformed("ByteRange '[' missing".into()))?;
    let close =
        find_sub(&s[open..], b"]").ok_or_else(|| Error::Malformed("ByteRange ']' missing".into()))?
            + open;
    let inner = std::str::from_utf8(&s[open + 1..close])
        .map_err(|_| Error::Malformed("ByteRange not ASCII".into()))?;
    let nums: Vec<i64> = inner
        .split_whitespace()
        .filter_map(|t| t.parse::<i64>().ok())
        .collect();
    if nums.len() != 4 {
        return Err(Error::Malformed(format!(
            "expected 4 ByteRange ints, got {}",
            nums.len()
        )));
    }
    Ok([nums[0], nums[1], nums[2], nums[3]])
}

/// Slice the real CMS out of the raw `/Contents` bytes, dropping the zero
/// padding using the ASN.1 length header.
fn cms_from_contents(contents: &[u8]) -> Result<Vec<u8>> {
    if contents.first() != Some(&0x30) {
        return Err(Error::Malformed("CMS does not start with SEQUENCE".into()));
    }
    let len = der_total_len(contents)
        .ok_or_else(|| Error::Malformed("cannot read CMS DER length".into()))?;
    if len > contents.len() {
        return Err(Error::Malformed("CMS DER length exceeds placeholder".into()));
    }
    Ok(contents[..len].to_vec())
}

/// True if the ByteRange gap `[gap_start, gap_end)` is exactly the `/Contents`
/// hex string `<...>` whose decoded value is `contents` — i.e. the signature
/// excludes nothing but its own Contents.
fn gap_is_contents(pdf: &[u8], gap_start: usize, gap_end: usize, contents: &[u8]) -> bool {
    if gap_start >= gap_end || gap_end > pdf.len() {
        return false;
    }
    let gt = gap_end - 1;
    pdf.get(gap_start) == Some(&b'<')
        && pdf.get(gt) == Some(&b'>')
        && hex_decode(&pdf[gap_start + 1..gt]).as_deref() == Some(contents)
}
