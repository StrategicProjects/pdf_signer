//! Signing path: insert a signature field + `adbe.pkcs7.detached` CMS signature.

use std::path::Path;

use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat};

use crate::crypto::cms_sign;
use crate::error::Error;
use crate::util::{find_sub, hex_encode};
use crate::Result;

/// A visible signature appearance, rendered as the widget's `/AP /N` stream.
///
/// Coordinates are in PDF user-space points (origin at the page's bottom-left).
/// The box occupies `[x, y, x + width, y + height]` on page `page` (1-based).
#[derive(Debug, Clone)]
pub struct Appearance {
    /// 1-based page number the signature box is drawn on.
    pub page: usize,
    /// Lower-left X of the box, in points.
    pub x: f64,
    /// Lower-left Y of the box, in points.
    pub y: f64,
    /// Box width, in points.
    pub width: f64,
    /// Box height, in points.
    pub height: f64,
    /// Font size, in points.
    pub font_size: f64,
    /// Text to render. Wrapped to the box width; `\n` forces a line break.
    pub text: String,
    /// Draw a thin rectangle border around the box.
    pub border: bool,
}

impl Default for Appearance {
    fn default() -> Self {
        Self {
            page: 1,
            x: 36.0,
            y: 36.0,
            width: 260.0,
            height: 70.0,
            font_size: 8.0,
            text: String::new(),
            border: true,
        }
    }
}

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
    /// Optional visible appearance. When `None`, the signature is invisible
    /// (zero-area widget).
    pub appearance: Option<Appearance>,
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
            appearance: None,
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
    let page = opts.appearance.as_ref().map(|a| a.page).unwrap_or(1);
    let field_id = add_signature_field(&mut doc, opts)?;
    attach_field_to_page(&mut doc, field_id, page)?;
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

    // Build the visible appearance stream first (if any), so we can reference it.
    let appearance = opts
        .appearance
        .as_ref()
        .map(|app| build_appearance_xobject(doc, app))
        .transpose()?;

    let mut field = Dictionary::new();
    field.set("Type", Object::Name(b"Annot".to_vec()));
    field.set("Subtype", Object::Name(b"Widget".to_vec()));
    field.set("FT", Object::Name(b"Sig".to_vec()));
    field.set("T", Object::string_literal("Signature1"));
    field.set("F", Object::Integer(132)); // Print | Locked
    field.set("V", Object::Reference(sig_id));

    match (&opts.appearance, appearance) {
        (Some(app), Some(ap_id)) => {
            let rect = rect_array(app.x, app.y, app.x + app.width, app.y + app.height);
            field.set("Rect", rect);
            let mut ap = Dictionary::new();
            ap.set("N", Object::Reference(ap_id));
            field.set("AP", Object::Dictionary(ap));
        }
        _ => {
            // Invisible signature: zero-area rectangle.
            field.set("Rect", rect_array(0.0, 0.0, 0.0, 0.0));
        }
    }

    let field_id = doc.add_object(Object::Dictionary(field));
    Ok(field_id)
}

fn rect_array(x1: f64, y1: f64, x2: f64, y2: f64) -> Object {
    Object::Array(vec![
        Object::Real(x1 as f32),
        Object::Real(y1 as f32),
        Object::Real(x2 as f32),
        Object::Real(y2 as f32),
    ])
}

/// Build the appearance Form XObject (with a Helvetica font resource) and add
/// it to the document. Returns its object id.
fn build_appearance_xobject(doc: &mut Document, app: &Appearance) -> Result<ObjectId> {
    let font_id = doc.add_object({
        let mut f = Dictionary::new();
        f.set("Type", Object::Name(b"Font".to_vec()));
        f.set("Subtype", Object::Name(b"Type1".to_vec()));
        f.set("BaseFont", Object::Name(b"Helvetica".to_vec()));
        f.set("Encoding", Object::Name(b"WinAnsiEncoding".to_vec()));
        Object::Dictionary(f)
    });

    let content = build_appearance_content(app);

    let mut resources = Dictionary::new();
    let mut fonts = Dictionary::new();
    fonts.set("Helv", Object::Reference(font_id));
    resources.set("Font", Object::Dictionary(fonts));

    let mut xobj = Dictionary::new();
    xobj.set("Type", Object::Name(b"XObject".to_vec()));
    xobj.set("Subtype", Object::Name(b"Form".to_vec()));
    xobj.set("FormType", Object::Integer(1));
    xobj.set("BBox", rect_array(0.0, 0.0, app.width, app.height));
    xobj.set("Resources", Object::Dictionary(resources));

    let stream = lopdf::Stream::new(xobj, content);
    Ok(doc.add_object(Object::Stream(stream)))
}

/// Render the appearance content stream: optional border + wrapped text.
fn build_appearance_content(app: &Appearance) -> Vec<u8> {
    let margin = 2.0_f64;
    let fs = app.font_size;
    let leading = fs * 1.2;
    let max_w = (app.width - 2.0 * margin).max(1.0);
    let lines = wrap_text(&app.text, max_w, fs);
    let start_y = app.height - margin - fs;

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"q\n");
    if app.border {
        out.extend_from_slice(
            format!(
                "0.5 0.5 0.5 RG 0.75 w 0.50 0.50 {:.2} {:.2} re S\n",
                app.width - 1.0,
                app.height - 1.0
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(b"0 0 0 rg\nBT\n");
    out.extend_from_slice(format!("/Helv {:.2} Tf\n", fs).as_bytes());
    out.extend_from_slice(format!("{:.2} TL\n", leading).as_bytes());
    out.extend_from_slice(format!("{:.2} {:.2} Td\n", margin, start_y).as_bytes());
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b"T* ");
        }
        out.push(b'(');
        out.extend_from_slice(&encode_winansi_escaped(line));
        out.extend_from_slice(b") Tj\n");
    }
    out.extend_from_slice(b"ET\nQ\n");
    out
}

/// Encode a line to WinAnsi bytes and escape the PDF literal-string specials.
/// Characters outside Latin-1 are replaced with `?` (best effort for the PoC).
fn encode_winansi_escaped(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 4);
    for ch in s.chars() {
        let b = if (ch as u32) <= 0xFF { ch as u8 } else { b'?' };
        if matches!(b, b'(' | b')' | b'\\') {
            v.push(b'\\');
        }
        v.push(b);
    }
    v
}

/// Greedy word-wrap using an approximate average Helvetica glyph width
/// (~0.5 em). `\n` in the input forces hard line breaks.
fn wrap_text(text: &str, max_width: f64, font_size: f64) -> Vec<String> {
    let char_w = (font_size * 0.5).max(0.1);
    let max_chars = ((max_width / char_w).floor() as usize).max(1);

    let mut out = Vec::new();
    for para in text.split('\n') {
        let para = para.trim_end();
        if para.is_empty() {
            out.push(String::new());
            continue;
        }
        let mut cur = String::new();
        for word in para.split_whitespace() {
            if cur.is_empty() {
                if word.chars().count() > max_chars {
                    // A single word longer than the line: hard-split it.
                    let mut chunk = String::new();
                    for c in word.chars() {
                        if chunk.chars().count() >= max_chars {
                            out.push(std::mem::take(&mut chunk));
                        }
                        chunk.push(c);
                    }
                    cur = chunk;
                } else {
                    cur = word.to_string();
                }
            } else if cur.chars().count() + 1 + word.chars().count() <= max_chars {
                cur.push(' ');
                cur.push_str(word);
            } else {
                out.push(std::mem::take(&mut cur));
                cur = word.to_string();
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
    }
    out
}

/// Append the widget reference to the `/Annots` of page `page_number` (1-based),
/// falling back to the first page.
fn attach_field_to_page(doc: &mut Document, field_id: ObjectId, page_number: usize) -> Result<()> {
    let pages = doc.get_pages();
    let page_id = pages
        .get(&(page_number as u32))
        .copied()
        .or_else(|| pages.values().next().copied())
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
