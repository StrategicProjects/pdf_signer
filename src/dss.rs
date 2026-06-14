//! Document Security Store (DSS) for PAdES-B-LT.
//!
//! Gathers the validation material — every certificate involved (signer chain
//! plus the TSA chain embedded in the signature timestamp) and, best-effort,
//! the CRLs referenced by those certificates — and embeds it in a `/DSS`
//! dictionary added to the document catalog via an incremental update. This is
//! what lets a signature be validated long after the issuing CA / TSA services
//! are gone.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};

use lopdf::{Dictionary, Document, Object, Stream};

use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::CrlDistributionPoints;
use x509_cert::Certificate;

use crate::error::Error;
use crate::incremental::{last_startxref, Incremental};
use crate::Result;

const ID_AA_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// Certificates and CRLs to embed in the DSS (all DER-encoded).
pub(crate) struct ValidationMaterial {
    pub certs: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
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
            for url in crl_http_urls(&cert) {
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

    Ok(ValidationMaterial { certs, crls })
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

fn crl_http_urls(cert: &Certificate) -> Vec<String> {
    let mut urls = Vec::new();
    if let Ok(Some((_, cdp))) = cert.tbs_certificate.get::<CrlDistributionPoints>() {
        for dp in cdp.0.iter() {
            if let Some(DistributionPointName::FullName(names)) = &dp.distribution_point {
                for name in names {
                    if let GeneralName::UniformResourceIdentifier(uri) = name {
                        let s = uri.as_str().to_string();
                        if s.starts_with("http://") {
                            urls.push(s);
                        }
                    }
                }
            }
        }
    }
    urls
}

/// Append a `/DSS` dictionary (with `/Certs` and `/CRLs`) to the catalog as an
/// incremental update.
pub(crate) fn add_dss(pdf: &[u8], material: &ValidationMaterial) -> Result<Vec<u8>> {
    let doc = Document::load_mem(pdf)?;
    let root_id = doc.trailer.get(b"Root")?.as_reference()?;

    let mut inc = Incremental::new(pdf);
    let mut next_id = doc.max_id + 1;
    let mut alloc = || {
        let id = (next_id, 0u16);
        next_id += 1;
        id
    };

    let mut dss = Dictionary::new();

    let mut cert_refs = Vec::new();
    for der in &material.certs {
        let id = alloc();
        inc.add(id, der_stream(der));
        cert_refs.push(Object::Reference(id));
    }
    if !cert_refs.is_empty() {
        dss.set("Certs", Object::Array(cert_refs));
    }

    let mut crl_refs = Vec::new();
    for der in &material.crls {
        let id = alloc();
        inc.add(id, der_stream(der));
        crl_refs.push(Object::Reference(id));
    }
    if !crl_refs.is_empty() {
        dss.set("CRLs", Object::Array(crl_refs));
    }

    // Re-emit the catalog with the new /DSS entry, preserving everything else.
    let mut catalog = doc.get_object(root_id)?.as_dict()?.clone();
    catalog.set("DSS", Object::Dictionary(dss));
    inc.add(root_id, Object::Dictionary(catalog));

    let size = next_id;
    let prev = last_startxref(pdf)
        .ok_or_else(|| Error::Malformed("original PDF has no startxref".into()))?;
    let id_array = doc.trailer.get(b"ID").ok().cloned();
    Ok(inc.render(size, root_id, prev, id_array))
}

/// A stream object whose content is the given DER blob (no filter).
fn der_stream(der: &[u8]) -> Object {
    Object::Stream(Stream::new(Dictionary::new(), der.to_vec()))
}

/// Extract the DER of every CRL stored in the document's `/DSS /CRLs`, for use
/// in revocation checking. Returns an empty vec if there is no DSS.
pub(crate) fn extract_dss_crls(pdf: &[u8]) -> Vec<Vec<u8>> {
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
    let Ok(crls) = dss.get(b"CRLs").and_then(|o| o.as_array()) else {
        return out;
    };
    for item in crls {
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
