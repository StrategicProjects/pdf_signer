//! Document Security Store (DSS) for PAdES-B-LT.
//!
//! Gathers the validation material — every certificate involved (signer chain
//! plus the TSA chain embedded in the signature timestamp) and, best-effort,
//! the CRLs and OCSP responses referenced by those certificates — and merges it
//! into the `/DSS` dictionary of the document catalog via an incremental
//! update. This is what lets a signature be validated long after the issuing
//! CA / TSA services are gone.
//!
//! Fetching is best-effort: an unreachable distribution point or responder is
//! skipped, so a B-LT signature produced offline may carry certificates only.
//! Verification treats missing revocation evidence as soft-fail (see
//! `trust.rs`).

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;

use const_oid::db::rfc5912::ID_AD_OCSP;
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};

use lopdf::{Dictionary, Document, Object, Stream};

use sha1::Sha1;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};
use x509_cert::Certificate;
use x509_ocsp::builder::OcspRequestBuilder;
use x509_ocsp::{OcspResponse, OcspResponseStatus, Request};

use crate::error::Error;
use crate::incremental::{last_startxref, Incremental};
use crate::sign::load_for_update;
use crate::Result;

const ID_AA_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// Certificates, CRLs and OCSP responses to embed in the DSS (all DER-encoded).
pub(crate) struct ValidationMaterial {
    pub certs: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    pub ocsps: Vec<Vec<u8>>,
}

/// Collect the validation material implied by a signature's CMS: all embedded
/// certificates (including the timestamp token's) plus their CRLs.
pub(crate) fn collect_validation_material(signature_cms: &[u8]) -> Result<ValidationMaterial> {
    let mut certs: Vec<Vec<u8>> = Vec::new();
    collect_certs(signature_cms, &mut certs)?;
    if let Some(token) = extract_timestamp_token(signature_cms)? {
        collect_certs(&token, &mut certs)?;
    }
    certs.sort();
    certs.dedup();

    // Best-effort CRL fetch from each certificate's HTTP distribution points.
    let mut urls: Vec<String> = Vec::new();
    for der in &certs {
        if let Ok(cert) = Certificate::from_der(der) {
            for url in crl_urls(&cert) {
                if !urls.contains(&url) {
                    urls.push(url);
                }
            }
        }
    }
    let mut crls: Vec<Vec<u8>> = Vec::new();
    for url in urls {
        if let Ok(body) = crate::tsa::http_get(&url) {
            // Accept only DER (SEQUENCE); some endpoints serve PEM or HTML.
            if body.first() == Some(&0x30) {
                crls.push(body);
            }
        }
    }
    crls.sort();
    crls.dedup();

    // Best-effort OCSP responses for each non-root cert (needs its issuer).
    let parsed: Vec<Certificate> = certs
        .iter()
        .filter_map(|d| Certificate::from_der(d).ok())
        .collect();
    let mut ocsps: Vec<Vec<u8>> = Vec::new();
    for cert in &parsed {
        if let Some(resp) = fetch_ocsp(cert, &parsed) {
            ocsps.push(resp);
        }
    }
    ocsps.sort();
    ocsps.dedup();

    Ok(ValidationMaterial { certs, crls, ocsps })
}

/// Request an OCSP response for `cert` from its issuer's responder (AIA).
/// Returns the raw `OCSPResponse` DER on a successful status, else `None`.
fn fetch_ocsp(cert: &Certificate, pool: &[Certificate]) -> Option<Vec<u8>> {
    // Find the issuer in the pool (subject == cert.issuer), skipping self.
    let issuer = pool.iter().find(|c| {
        let s = c.tbs_certificate.subject.to_der().ok();
        let i = cert.tbs_certificate.issuer.to_der().ok();
        s.is_some() && s == i && !same_der(c, cert)
    })?;

    let url = ocsp_url(cert)?;
    let request =
        Request::from_issuer::<Sha1>(issuer, cert.tbs_certificate.serial_number.clone()).ok()?;
    let body = OcspRequestBuilder::default()
        .with_request(request)
        .build()
        .to_der()
        .ok()?;
    let raw = crate::tsa::http_post(&url, "application/ocsp-request", &body).ok()?;

    let resp = OcspResponse::from_der(&raw).ok()?;
    if resp.response_status == OcspResponseStatus::Successful {
        Some(raw)
    } else {
        None
    }
}

/// True if we can fetch `url`: plain `http://` always, `https://` only when the
/// `https` feature (and thus a TLS stack) is compiled in.
fn fetchable_url(url: &str) -> bool {
    url.starts_with("http://") || (cfg!(feature = "https") && url.starts_with("https://"))
}

/// The OCSP responder URL from a certificate's Authority Information Access.
fn ocsp_url(cert: &Certificate) -> Option<String> {
    let (_, aia) = cert.tbs_certificate.get::<AuthorityInfoAccessSyntax>().ok()??;
    for desc in aia.0.iter() {
        if desc.access_method == ID_AD_OCSP {
            if let GeneralName::UniformResourceIdentifier(uri) = &desc.access_location {
                let s = uri.as_str().to_string();
                if fetchable_url(&s) {
                    return Some(s);
                }
            }
        }
    }
    None
}

fn same_der(a: &Certificate, b: &Certificate) -> bool {
    matches!((a.to_der(), b.to_der()), (Ok(x), Ok(y)) if x == y)
}

fn collect_certs(cms_der: &[u8], out: &mut Vec<Vec<u8>>) -> Result<()> {
    let ci = ContentInfo::from_der(cms_der).map_err(map)?;
    let sd = ci.content.decode_as::<SignedData>().map_err(map)?;
    if let Some(set) = &sd.certificates {
        for choice in set.0.iter() {
            if let CertificateChoices::Certificate(cert) = choice {
                out.push(cert.to_der().map_err(map)?);
            }
        }
    }
    Ok(())
}

/// Return the DER of the `id-aa-timeStampToken` unsigned attribute, if present.
fn extract_timestamp_token(cms_der: &[u8]) -> Result<Option<Vec<u8>>> {
    let ci = ContentInfo::from_der(cms_der).map_err(map)?;
    let sd = ci.content.decode_as::<SignedData>().map_err(map)?;
    let Some(si) = sd.signer_infos.0.iter().next() else {
        return Ok(None);
    };
    let Some(unsigned) = &si.unsigned_attrs else {
        return Ok(None);
    };
    for attr in unsigned.iter() {
        if attr.oid == ID_AA_TIME_STAMP_TOKEN {
            if let Some(value) = attr.values.iter().next() {
                return Ok(Some(value.to_der().map_err(map)?));
            }
        }
    }
    Ok(None)
}

fn crl_urls(cert: &Certificate) -> Vec<String> {
    let mut urls = Vec::new();
    if let Ok(Some((_, cdp))) = cert.tbs_certificate.get::<CrlDistributionPoints>() {
        for dp in cdp.0.iter() {
            if let Some(DistributionPointName::FullName(names)) = &dp.distribution_point {
                for name in names {
                    if let GeneralName::UniformResourceIdentifier(uri) = name {
                        let s = uri.as_str().to_string();
                        if fetchable_url(&s) {
                            urls.push(s);
                        }
                    }
                }
            }
        }
    }
    urls
}

/// Append validation material to the catalog's `/DSS` as an incremental
/// update, **merging** with any Document Security Store already present
/// (ETSI EN 319 142-1 §5.4.2: an updated DSS keeps the earlier values). Streams
/// whose DER is already referenced are not duplicated; `/VRI` and any other
/// existing entries are preserved. A `/DSS` held as an indirect object is
/// rewritten in place; an inline one stays inline.
pub(crate) fn add_dss(pdf: &[u8], material: &ValidationMaterial) -> Result<Vec<u8>> {
    let doc = load_for_update(pdf)?;
    let root_id = doc.trailer.get(b"Root")?.as_reference()?;
    let catalog = doc.get_object(root_id)?.as_dict()?.clone();

    // Existing DSS (inline or referenced) and where it lives.
    let (mut dss, dss_ref): (Dictionary, Option<lopdf::ObjectId>) = match catalog.get(b"DSS") {
        Ok(Object::Dictionary(d)) => (d.clone(), None),
        Ok(Object::Reference(r)) => match doc.get_object(*r).and_then(|o| o.as_dict()) {
            Ok(d) => (d.clone(), Some(*r)),
            Err(_) => (Dictionary::new(), None),
        },
        _ => (Dictionary::new(), None),
    };

    let mut inc = Incremental::new(pdf);
    let mut next_id = doc.max_id + 1;
    let mut alloc = || {
        let id = (next_id, 0u16);
        next_id += 1;
        id
    };

    // Merge one array (`/Certs`, `/CRLs`, `/OCSPs`): keep existing references,
    // add a stream for each DER blob not already present.
    let mut merge = |key: &str, ders: &[Vec<u8>]| {
        let mut refs: Vec<Object> = match dss.get(key.as_bytes()) {
            Ok(Object::Array(a)) => a.clone(),
            Ok(Object::Reference(r)) => doc
                .get_object(*r)
                .and_then(|o| o.as_array())
                .cloned()
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let existing: Vec<Vec<u8>> = refs
            .iter()
            .filter_map(|o| o.as_reference().ok())
            .filter_map(|id| doc.get_object(id).ok())
            .filter_map(|o| o.as_stream().ok())
            .map(|s| s.decompressed_content().unwrap_or_else(|_| s.content.clone()))
            .collect();
        for der in ders {
            if existing.iter().any(|e| e == der) {
                continue;
            }
            let id = alloc();
            inc.add(id, der_stream(der));
            refs.push(Object::Reference(id));
        }
        if !refs.is_empty() {
            dss.set(key, Object::Array(refs));
        }
    };
    merge("Certs", &material.certs);
    merge("CRLs", &material.crls);
    merge("OCSPs", &material.ocsps);

    // Re-emit the DSS where it lives; the catalog only when the DSS is inline.
    match dss_ref {
        Some(id) => inc.add(id, Object::Dictionary(dss)),
        None => {
            let mut catalog = catalog;
            catalog.set("DSS", Object::Dictionary(dss));
            inc.add(root_id, Object::Dictionary(catalog));
        }
    }

    let size = next_id;
    let prev = last_startxref(pdf)
        .ok_or_else(|| Error::Malformed("original PDF has no startxref".into()))?;
    Ok(inc.render(size, root_id, prev, &doc.trailer).bytes)
}

/// A stream object whose content is the given DER blob (no filter).
fn der_stream(der: &[u8]) -> Object {
    Object::Stream(Stream::new(Dictionary::new(), der.to_vec()))
}

/// Extract the DER of every CRL stored in the document's `/DSS /CRLs`.
pub(crate) fn extract_dss_crls(pdf: &[u8]) -> Vec<Vec<u8>> {
    extract_dss_streams(pdf, b"CRLs")
}

/// Extract the DER of every OCSP response stored in `/DSS /OCSPs`.
pub(crate) fn extract_dss_ocsps(pdf: &[u8]) -> Vec<Vec<u8>> {
    extract_dss_streams(pdf, b"OCSPs")
}

/// Extract the raw content of each stream referenced by `/DSS/<key>`.
fn extract_dss_streams(pdf: &[u8], key: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Ok(doc) = Document::load_mem(pdf) else {
        return out;
    };
    let Ok(root_id) = doc.trailer.get(b"Root").and_then(|o| o.as_reference()) else {
        return out;
    };
    let Ok(catalog) = doc.get_object(root_id).and_then(|o| o.as_dict()) else {
        return out;
    };
    // /DSS may be an inline dict or a reference.
    let dss = match catalog.get(b"DSS") {
        Ok(Object::Dictionary(d)) => d.clone(),
        Ok(Object::Reference(r)) => match doc.get_object(*r).and_then(|o| o.as_dict()) {
            Ok(d) => d.clone(),
            Err(_) => return out,
        },
        _ => return out,
    };
    let Ok(items) = dss.get(key).and_then(|o| o.as_array()) else {
        return out;
    };
    for item in items {
        if let Ok(id) = item.as_reference() {
            if let Ok(stream) = doc.get_object(id).and_then(|o| o.as_stream()) {
                out.push(
                    stream
                        .decompressed_content()
                        .unwrap_or_else(|_| stream.content.clone()),
                );
            }
        }
    }
    out
}

fn map<E: std::fmt::Display>(e: E) -> Error {
    Error::Crypto(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::fetchable_url;

    #[test]
    fn plain_http_is_always_fetchable() {
        assert!(fetchable_url("http://ca.example/crl.der"));
        assert!(!fetchable_url("ldap://ca.example/cn"));
        assert!(!fetchable_url("ftp://ca.example/crl.der"));
    }

    #[test]
    fn https_follows_the_feature_flag() {
        // HTTPS is only fetchable when a TLS stack is compiled in.
        assert_eq!(
            fetchable_url("https://ca.example/crl.der"),
            cfg!(feature = "https")
        );
    }
}
