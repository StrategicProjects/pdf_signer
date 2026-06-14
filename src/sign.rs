//! Signing path: insert a signature field + `adbe.pkcs7.detached` CMS signature.

use std::path::Path;

use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkcs12::Pkcs12;
use openssl::stack::Stack;
use openssl::x509::X509;

use crate::error::Error;
use crate::util::{find_sub, hex_encode};
use crate::Result;

/// Options controlling the signature dictionary metadata.
#[derive(Debug, Clone)]
pub struct SignOptions {
    /// Bytes reserved for the CMS blob inside `/Contents`. The hex placeholder
    /// is twice this size. Must exceed the produced signature length.
    pub signature_capacity: usize,
    /// Optional `/Reason` for signing.
    pub reason: Option<String>,
    /// Optional human `/Name` of the signer.
    pub name: Option<String>,
    /// Optional `/Location`.
    pub location: Option<String>,
    /// Optional `/ContactInfo`.
    pub contact_info: Option<String>,
    /// Optional signing time, already formatted as a PDF date, e.g.
    /// `D:20260614120000Z`.
    pub signing_time: Option<String>,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self {
            signature_capacity: 16384,
            reason: None,
            name: None,
            location: None,
            contact_info: None,
            signing_time: None,
        }
    }
}

/// Sign `input` PDF, writing the signed PDF to `output`.
pub fn sign_pdf_file(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    keystore: impl AsRef<Path>,
    password: &str,
    opts: &SignOptions,
) -> Result<()> {
    let pdf = std::fs::read(input)?;
    let p12 = std::fs::read(keystore)?;
    let signed = sign_pdf_bytes(&pdf, &p12, password, opts)?;
    std::fs::write(output, signed)?;
    Ok(())
}

/// Sign an in-memory PDF with an in-memory PKCS#12 keystore.
pub fn sign_pdf_bytes(
    pdf: &[u8],
    keystore_p12: &[u8],
    password: &str,
    opts: &SignOptions,
) -> Result<Vec<u8>> {
    // 1. Lay out the signature dictionary + field with placeholders.
    let mut doc = Document::load_mem(pdf)?;
    let field_id = add_signature_field(&mut doc, opts)?;
    attach_field_to_first_page(&mut doc, field_id)?;
    set_acroform(&mut doc, field_id)?;

    // 2. Serialize once; from here byte offsets are stable.
    let mut buf = Vec::new();
    doc.save_to(&mut buf)?;

    // 3. Locate the /Contents placeholder (the hex string of zeros).
    let (lt, gt) = locate_contents_placeholder(&buf, opts.signature_capacity)?;
    let p = lt; // index of '<'
    let q = gt + 1; // index just after '>'
    let total = buf.len();

    // 4. Patch the /ByteRange in place (length-preserving, so p/q stay valid).
    patch_byte_range(&mut buf, p as i64, q as i64, (total - q) as i64)?;

    // 5. Build the detached CMS over everything except the Contents hole.
    let mut signed_bytes = Vec::with_capacity(p + (total - q));
    signed_bytes.extend_from_slice(&buf[..p]);
    signed_bytes.extend_from_slice(&buf[q..]);
    let der = cms_sign(keystore_p12, password, &signed_bytes)?;

    // 6. Write the signature hex into the placeholder.
    let hex = hex_encode(&der);
    let capacity_hex = opts.signature_capacity * 2;
    if hex.len() > capacity_hex {
        return Err(Error::PlaceholderTooSmall {
            needed: der.len(),
            capacity: opts.signature_capacity,
        });
    }
    let region = &mut buf[lt + 1..lt + 1 + capacity_hex];
    for b in region.iter_mut() {
        *b = b'0';
    }
    region[..hex.len()].copy_from_slice(&hex);

    Ok(buf)
}

/// Create the signature `/Sig` object and a `/FT /Sig` widget field that
/// references it. Returns the field (widget) object id.
fn add_signature_field(doc: &mut Document, opts: &SignOptions) -> Result<ObjectId> {
    let mut sig = Dictionary::new();
    sig.set("Type", Object::Name(b"Sig".to_vec()));
    sig.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig.set("SubFilter", Object::Name(b"adbe.pkcs7.detached".to_vec()));
    // Placeholders patched after serialization. Ten-digit sentinels reserve
    // enough width for any realistic file offset.
    sig.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(9_999_999_999),
            Object::Integer(9_999_999_999),
            Object::Integer(9_999_999_999),
        ]),
    );
    sig.set(
        "Contents",
        Object::String(vec![0u8; opts.signature_capacity], StringFormat::Hexadecimal),
    );
    if let Some(r) = &opts.reason {
        sig.set("Reason", Object::string_literal(r.clone()));
    }
    if let Some(n) = &opts.name {
        sig.set("Name", Object::string_literal(n.clone()));
    }
    if let Some(l) = &opts.location {
        sig.set("Location", Object::string_literal(l.clone()));
    }
    if let Some(c) = &opts.contact_info {
        sig.set("ContactInfo", Object::string_literal(c.clone()));
    }
    if let Some(t) = &opts.signing_time {
        sig.set("M", Object::string_literal(t.clone()));
    }
    let sig_id = doc.add_object(Object::Dictionary(sig));

    let mut field = Dictionary::new();
    field.set("Type", Object::Name(b"Annot".to_vec()));
    field.set("Subtype", Object::Name(b"Widget".to_vec()));
    field.set("FT", Object::Name(b"Sig".to_vec()));
    field.set("T", Object::string_literal("Signature1"));
    // Invisible signature: zero-area rectangle, print flag set.
    field.set(
        "Rect",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
        ]),
    );
    field.set("F", Object::Integer(132)); // Print | Locked
    field.set("V", Object::Reference(sig_id));
    let field_id = doc.add_object(Object::Dictionary(field));
    Ok(field_id)
}

/// Append the widget reference to the first page's `/Annots`.
fn attach_field_to_first_page(doc: &mut Document, field_id: ObjectId) -> Result<()> {
    let page_id = *doc
        .get_pages()
        .values()
        .next()
        .ok_or_else(|| Error::Malformed("PDF has no pages".into()))?;

    enum Kind {
        RefArray(ObjectId),
        Inline,
        None,
    }
    let kind = {
        let page = doc.get_object(page_id)?.as_dict()?;
        match page.get(b"Annots") {
            Ok(Object::Reference(r)) => Kind::RefArray(*r),
            Ok(Object::Array(_)) => Kind::Inline,
            _ => Kind::None,
        }
    };
    let field_ref = Object::Reference(field_id);
    match kind {
        Kind::RefArray(r) => doc.get_object_mut(r)?.as_array_mut()?.push(field_ref),
        Kind::Inline => doc
            .get_object_mut(page_id)?
            .as_dict_mut()?
            .get_mut(b"Annots")?
            .as_array_mut()?
            .push(field_ref),
        Kind::None => doc
            .get_object_mut(page_id)?
            .as_dict_mut()?
            .set("Annots", Object::Array(vec![field_ref])),
    }
    Ok(())
}

/// Register the field in the document catalog `/AcroForm` and flag it as signed.
fn set_acroform(doc: &mut Document, field_id: ObjectId) -> Result<()> {
    let root_id = doc.trailer.get(b"Root")?.as_reference()?;
    let mut acro = Dictionary::new();
    acro.set("Fields", Object::Array(vec![Object::Reference(field_id)]));
    acro.set("SigFlags", Object::Integer(3)); // SignaturesExist | AppendOnly
    doc.get_object_mut(root_id)?
        .as_dict_mut()?
        .set("AcroForm", Object::Dictionary(acro));
    Ok(())
}

/// Find the `< 00..00 >` placeholder, returning the `<` and `>` indices.
fn locate_contents_placeholder(buf: &[u8], capacity: usize) -> Result<(usize, usize)> {
    // Search after /ByteRange so we never collide with a page's /Contents.
    let br = find_sub(buf, b"/ByteRange")
        .ok_or_else(|| Error::Malformed("/ByteRange not found".into()))?;
    let rel = find_sub(&buf[br..], b"/Contents")
        .ok_or_else(|| Error::Malformed("/Contents not found".into()))?;
    let from = br + rel;
    let lt_rel = find_sub(&buf[from..], b"<")
        .ok_or_else(|| Error::Malformed("Contents '<' not found".into()))?;
    let lt = from + lt_rel;
    let gt = lt + 1 + capacity * 2;
    if gt >= buf.len() || buf[gt] != b'>' {
        return Err(Error::Malformed(
            "Contents placeholder size mismatch".into(),
        ));
    }
    Ok((lt, gt))
}

/// Replace the `/ByteRange [...]` array with concrete offsets, padding with
/// spaces so the byte length is unchanged.
fn patch_byte_range(buf: &mut [u8], a: i64, b: i64, c: i64) -> Result<()> {
    let br = find_sub(buf, b"/ByteRange")
        .ok_or_else(|| Error::Malformed("/ByteRange not found".into()))?;
    let open = br + find_sub(&buf[br..], b"[")
        .ok_or_else(|| Error::Malformed("ByteRange '[' not found".into()))?;
    let close = open
        + find_sub(&buf[open..], b"]").ok_or_else(|| Error::Malformed("ByteRange ']' not found".into()))?;
    let span = close - open + 1;
    let mut replacement = format!("[0 {} {} {}]", a, b, c).into_bytes();
    if replacement.len() > span {
        return Err(Error::Malformed("ByteRange placeholder too small".into()));
    }
    // Pad with spaces just before the closing ']'.
    while replacement.len() < span {
        replacement.insert(replacement.len() - 1, b' ');
    }
    buf[open..=close].copy_from_slice(&replacement);
    Ok(())
}

/// Produce a detached CMS (PKCS#7) signature over `data` using the keystore.
fn cms_sign(keystore_p12: &[u8], password: &str, data: &[u8]) -> Result<Vec<u8>> {
    let pkcs12 = Pkcs12::from_der(keystore_p12)?;
    let parsed = pkcs12.parse2(password)?;
    let cert = parsed
        .cert
        .ok_or_else(|| Error::Malformed("keystore has no certificate".into()))?;
    let pkey = parsed
        .pkey
        .ok_or_else(|| Error::Malformed("keystore has no private key".into()))?;

    let mut chain = Stack::<X509>::new()?;
    if let Some(ca) = parsed.ca {
        for c in ca {
            chain.push(c)?;
        }
    }

    // DETACHED: data is not embedded. BINARY: no CRLF canonicalization.
    let flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;
    let pkcs7 = Pkcs7::sign(&cert, &pkey, &chain, data, flags)?;
    Ok(pkcs7.to_der()?)
}
