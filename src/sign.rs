//! Signing path: insert a signature field + `ETSI.CAdES.detached` CMS signature.

use std::path::Path;

use der::Encode;
use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat};

use crate::crypto::cms_sign;
use crate::error::Error;
use crate::incremental::{last_startxref, text_string, Incremental, Rendered};
use crate::util::{find_sub, hex_encode};
use crate::Result;

/// PAdES conformance level to produce.
///
/// Levels are cumulative: each adds material on top of the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum PadesLevel {
    /// Baseline: CAdES `signing-certificate-v2`.
    #[default]
    Bb,
    /// B-B + an RFC 3161 signature timestamp (needs `tsa_url`).
    Bt,
    /// B-T + a Document Security Store (certificates + CRLs + OCSP).
    Blt,
    /// B-LT + a document timestamp over the whole file (needs `tsa_url`).
    Blta,
}

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
    /// Optional TrueType/OpenType font to embed (a simple WinAnsi font). When
    /// `None`, the standard Helvetica is used.
    pub font: Option<Vec<u8>>,
    /// Optional logo image (PNG or JPEG) drawn in the box.
    pub image: Option<Vec<u8>>,
    /// Image placement `[x, y, width, height]` in box points. When `None`, the
    /// image is drawn on the left, fitted to the box height (keeping its
    /// aspect ratio), and the text starts to its right.
    pub image_rect: Option<[f64; 4]>,
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
            font: None,
            image: None,
            image_rect: None,
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
    /// Optional claimed signing time for the dictionary's `/M` entry, already
    /// formatted as a PDF date, e.g. `D:20260614120000Z`. When `None`, the
    /// current UTC time is written (PAdES baseline requires `/M`).
    pub signing_time: Option<String>,
    /// Optional visible appearance. When `None`, the signature is invisible
    /// (zero-area widget).
    pub appearance: Option<Appearance>,
    /// Optional RFC 3161 Time-Stamping Authority URL (`http://`, or `https://`
    /// with the `https` feature). Required for `PadesLevel::Bt` and above.
    pub tsa_url: Option<String>,
    /// Target PAdES conformance level.
    pub pades_level: PadesLevel,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self {
            // Generous: must fit the CMS plus, optionally, an RFC 3161
            // timestamp token (which carries the TSA certificate chain).
            signature_capacity: 30000,
            reason: None,
            name: None,
            location: None,
            contact_info: None,
            signing_time: None,
            appearance: None,
            tsa_url: None,
            pades_level: PadesLevel::Bb,
        }
    }
}

/// Sign `input` PDF, writing the signed PDF to `output`.
///
/// The output is written to a temporary file next to `output` and renamed into
/// place, so a failure never leaves a truncated file behind (and `output` may
/// safely equal `input`).
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
    write_atomic(output.as_ref(), &signed)
}

/// Write `data` to `path` via a temporary sibling file + rename.
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let file_name = path
        .file_name()
        .ok_or_else(|| Error::Io(std::io::Error::other("output path has no file name")))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = match dir {
        Some(d) => d.join(tmp_name),
        None => std::path::PathBuf::from(tmp_name),
    };
    if let Err(e) = std::fs::write(&tmp, data) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Sign an in-memory PDF with an in-memory PKCS#12 keystore.
pub fn sign_pdf_bytes(
    pdf: &[u8],
    keystore_p12: &[u8],
    password: &str,
    opts: &SignOptions,
) -> Result<Vec<u8>> {
    // PAdES-B-T and above embed an RFC 3161 timestamp, which needs a TSA. Fail
    // loudly here rather than silently downgrading the requested level to B-B.
    if opts.pades_level >= PadesLevel::Bt && opts.tsa_url.is_none() {
        return Err(Error::Crypto(format!(
            "PAdES-{:?} requires a tsa_url",
            opts.pades_level
        )));
    }
    let capacity_hex = opts
        .signature_capacity
        .checked_mul(2)
        .filter(|_| opts.signature_capacity > 0)
        .ok_or_else(|| Error::Malformed("invalid signature_capacity".into()))?;
    if let Some(app) = &opts.appearance {
        validate_appearance(app)?;
    }

    // 1. Build an incremental update (keeps the original bytes verbatim, so any
    //    prior signature stays valid).
    let (mut buf, sig_off) = build_incremental_update(pdf, opts)?;

    // 2. Locate the /Contents placeholder (the hex string of zeros) inside the
    //    signature object we just wrote — never by scanning arbitrary bytes.
    let (lt, gt) = locate_contents_placeholder(&buf, opts.signature_capacity, sig_off)?;
    let p = lt; // index of '<'
    let q = gt + 1; // index just after '>'
    let total = buf.len();

    // 3. Patch the /ByteRange in place (length-preserving, so p/q stay valid).
    patch_byte_range(&mut buf, sig_off, p as i64, q as i64, (total - q) as i64)?;

    // 4. Build the detached CMS over everything except the Contents hole.
    let mut signed_bytes = Vec::with_capacity(p + (total - q));
    signed_bytes.extend_from_slice(&buf[..p]);
    signed_bytes.extend_from_slice(&buf[q..]);
    // A signature timestamp (B-T+) needs a TSA; B-B does not.
    let sig_tsa = (opts.pades_level >= PadesLevel::Bt)
        .then_some(opts.tsa_url.as_deref())
        .flatten();
    let der = cms_sign(keystore_p12, password, &signed_bytes, sig_tsa)?;

    // 5. Write the signature hex into the placeholder.
    fill_placeholder(&mut buf, lt, capacity_hex, &der, opts.signature_capacity)?;

    // 6. PAdES-B-LT: add a Document Security Store with the validation material.
    if opts.pades_level >= PadesLevel::Blt {
        let material = crate::dss::collect_validation_material(&der)?;
        buf = crate::dss::add_dss(&buf, &material)?;
    }

    // 7. PAdES-B-LTA: add a document timestamp over the whole file (incl. DSS).
    if opts.pades_level >= PadesLevel::Blta {
        let url = opts
            .tsa_url
            .as_deref()
            .ok_or_else(|| Error::Crypto("PAdES-B-LTA requires a tsa_url".into()))?;
        buf = add_document_timestamp(&buf, url, opts.signature_capacity)?;
    }

    Ok(buf)
}

/// Hex-encode `der` into the placeholder starting at `lt` (`<`), zero-padded.
fn fill_placeholder(
    buf: &mut [u8],
    lt: usize,
    capacity_hex: usize,
    der: &[u8],
    capacity: usize,
) -> Result<()> {
    let hex = hex_encode(der);
    if hex.len() > capacity_hex {
        return Err(Error::PlaceholderTooSmall {
            needed: der.len(),
            capacity,
        });
    }
    let region = &mut buf[lt + 1..lt + 1 + capacity_hex];
    for b in region.iter_mut() {
        *b = b'0';
    }
    region[..hex.len()].copy_from_slice(&hex);
    Ok(())
}

/// Add a document timestamp (`/DocTimeStamp`, `/SubFilter /ETSI.RFC3161`) over
/// the whole file as an incremental update — the archival anchor of PAdES-B-LTA.
fn add_document_timestamp(pdf: &[u8], tsa_url: &str, capacity: usize) -> Result<Vec<u8>> {
    let (mut buf, ts_off) = build_doctimestamp_update(pdf, capacity)?;

    let (lt, gt) = locate_contents_placeholder(&buf, capacity, ts_off)?;
    let p = lt;
    let q = gt + 1;
    let total = buf.len();
    patch_byte_range(&mut buf, ts_off, p as i64, q as i64, (total - q) as i64)?;

    let mut signed = Vec::with_capacity(p + (total - q));
    signed.extend_from_slice(&buf[..p]);
    signed.extend_from_slice(&buf[q..]);

    // The timestamp imprint is over the document byte range itself.
    let token = crate::tsa::request_timestamp(tsa_url, &signed)?;
    let token_der = token.to_der().map_err(|e| Error::Malformed(e.to_string()))?;
    fill_placeholder(&mut buf, lt, capacity * 2, &token_der, capacity)?;
    Ok(buf)
}

/// Parse the document for an incremental update, refusing inputs this crate
/// cannot sign safely: encrypted files (the update would be written in clear
/// and the reader-side decryption would corrupt it) and documents certified
/// with a DocMDP permission of 1 (no changes allowed — a signature would
/// invalidate the certification).
pub(crate) fn load_for_update(pdf: &[u8]) -> Result<Document> {
    let doc = Document::load_mem(pdf)?;
    if doc.is_encrypted() || doc.encryption_state.is_some() {
        return Err(Error::Malformed(
            "the PDF is encrypted; signing encrypted documents is not supported".into(),
        ));
    }
    if docmdp_forbids_changes(&doc) {
        return Err(Error::Malformed(
            "the PDF is certified (DocMDP P=1: no changes allowed); adding a signature would invalidate it".into(),
        ));
    }
    Ok(doc)
}

/// True if the catalog's `/Perms /DocMDP` signature carries a transform with
/// `/P 1`.
fn docmdp_forbids_changes(doc: &Document) -> bool {
    let resolve = |o: &Object| -> Option<Dictionary> {
        match o {
            Object::Dictionary(d) => Some(d.clone()),
            Object::Reference(r) => doc.get_object(*r).ok()?.as_dict().ok().cloned(),
            _ => None,
        }
    };
    let Some(catalog) = doc.catalog().ok() else {
        return false;
    };
    let Some(perms) = catalog.get(b"Perms").ok().and_then(resolve) else {
        return false;
    };
    let Some(sig) = perms.get(b"DocMDP").ok().and_then(resolve) else {
        return false;
    };
    let Ok(refs) = sig.get(b"Reference").and_then(Object::as_array) else {
        return false;
    };
    refs.iter().filter_map(resolve).any(|r| {
        r.get(b"TransformMethod").ok().and_then(|o| o.as_name().ok()) == Some(b"DocMDP")
            && r
                .get(b"TransformParams")
                .ok()
                .and_then(resolve)
                .and_then(|tp| tp.get(b"P").ok().and_then(|p| p.as_i64().ok()))
                .unwrap_or(2)
                == 1
    })
}

/// Incremental update carrying an empty `/DocTimeStamp` signature field.
/// Returns the buffer and the offset of the timestamp dictionary object.
fn build_doctimestamp_update(pdf: &[u8], capacity: usize) -> Result<(Vec<u8>, usize)> {
    let doc = load_for_update(pdf)?;
    let root_id = doc.trailer.get(b"Root")?.as_reference()?;
    let page_id = nth_page_id(&doc, 1)?;

    let mut inc = Incremental::new(pdf);
    let mut next_id = doc.max_id + 1;

    let ts_id = alloc_id(&mut next_id);
    inc.add(ts_id, build_doctimestamp_dict(capacity));
    let widget_id = alloc_id(&mut next_id);
    // Reuse the invisible-widget builder (no appearance), pointing at the TS dict.
    inc.add(widget_id, build_widget(&SignOptions::default(), ts_id, None));

    apply_widget_to_page(&doc, &mut inc, page_id, widget_id)?;
    apply_field_to_acroform(&doc, &mut inc, root_id, widget_id)?;

    let size = next_id;
    let prev = last_startxref(pdf)
        .ok_or_else(|| Error::Malformed("original PDF has no startxref".into()))?;
    let Rendered { bytes, offsets } = inc.render(size, root_id, prev, &doc.trailer);
    Ok((bytes, offsets[&ts_id.0]))
}

/// The `/DocTimeStamp` dictionary with ByteRange/Contents placeholders.
fn build_doctimestamp_dict(capacity: usize) -> Object {
    let mut sig = Dictionary::new();
    sig.set("Type", Object::Name(b"DocTimeStamp".to_vec()));
    sig.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig.set("SubFilter", Object::Name(b"ETSI.RFC3161".to_vec()));
    sig.set("ByteRange", byte_range_placeholder());
    sig.set(
        "Contents",
        Object::String(vec![0u8; capacity], StringFormat::Hexadecimal),
    );
    Object::Dictionary(sig)
}

/// Ten-digit sentinels reserve enough width for any realistic file offset.
fn byte_range_placeholder() -> Object {
    Object::Array(vec![
        Object::Integer(0),
        Object::Integer(9_999_999_999),
        Object::Integer(9_999_999_999),
        Object::Integer(9_999_999_999),
    ])
}

/// Allocate the next object id (generation 0) and advance the counter.
fn alloc_id(next_id: &mut u32) -> ObjectId {
    let id = (*next_id, 0u16);
    *next_id += 1;
    id
}

/// Assemble the incremental-update section (with signature placeholders) and
/// return `original_bytes + update` plus the offset of the signature object.
fn build_incremental_update(pdf: &[u8], opts: &SignOptions) -> Result<(Vec<u8>, usize)> {
    let doc = load_for_update(pdf)?;
    let root_id = doc.trailer.get(b"Root")?.as_reference()?;
    let page_number = opts.appearance.as_ref().map(|a| a.page).unwrap_or(1);
    let page_id = nth_page_id(&doc, page_number)?;

    let mut inc = Incremental::new(pdf);
    let mut next_id = doc.max_id + 1;

    let sig_id = alloc_id(&mut next_id);
    inc.add(sig_id, build_sig_dict(opts));

    // Optional visible appearance (font, image, Form XObject).
    let mut ap_ref = None;
    if let Some(app) = &opts.appearance {
        ap_ref = Some(crate::appearance::add_appearance(&mut inc, &mut next_id, app)?);
    }

    let widget_id = alloc_id(&mut next_id);
    inc.add(widget_id, build_widget(opts, sig_id, ap_ref));

    apply_widget_to_page(&doc, &mut inc, page_id, widget_id)?;
    apply_field_to_acroform(&doc, &mut inc, root_id, widget_id)?;

    let size = next_id; // highest object id allocated + 1
    let prev = last_startxref(pdf)
        .ok_or_else(|| Error::Malformed("original PDF has no startxref".into()))?;
    let Rendered { bytes, offsets } = inc.render(size, root_id, prev, &doc.trailer);
    Ok((bytes, offsets[&sig_id.0]))
}

/// Reject appearance geometry that would serialize to invalid PDF numbers.
fn validate_appearance(app: &Appearance) -> Result<()> {
    let nums = [app.x, app.y, app.width, app.height, app.font_size];
    if nums.iter().any(|v| !v.is_finite()) {
        return Err(Error::Malformed("appearance geometry must be finite".into()));
    }
    if app.width <= 0.0 || app.height <= 0.0 || app.font_size <= 0.0 {
        return Err(Error::Malformed(
            "appearance width, height and font_size must be positive".into(),
        ));
    }
    if let Some(r) = app.image_rect {
        if r.iter().any(|v| !v.is_finite()) || r[2] <= 0.0 || r[3] <= 0.0 {
            return Err(Error::Malformed("invalid appearance image_rect".into()));
        }
    }
    if app.page == 0 {
        return Err(Error::Malformed("appearance page numbers are 1-based".into()));
    }
    Ok(())
}

/// Current UTC time as a PDF date string, `D:YYYYMMDDHHmmSSZ`.
fn pdf_date_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dt = der::DateTime::from_unix_duration(std::time::Duration::from_secs(secs))
        .unwrap_or(der::DateTime::new(1970, 1, 1, 0, 0, 0).expect("epoch"));
    format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minutes(),
        dt.seconds()
    )
}

/// The signature `/Sig` dictionary, with ByteRange/Contents placeholders.
fn build_sig_dict(opts: &SignOptions) -> Object {
    let mut sig = Dictionary::new();
    sig.set("Type", Object::Name(b"Sig".to_vec()));
    sig.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig.set("SubFilter", Object::Name(b"ETSI.CAdES.detached".to_vec()));
    sig.set("ByteRange", byte_range_placeholder());
    sig.set(
        "Contents",
        Object::String(vec![0u8; opts.signature_capacity], StringFormat::Hexadecimal),
    );
    if let Some(r) = &opts.reason {
        sig.set("Reason", text_string(r));
    }
    if let Some(n) = &opts.name {
        sig.set("Name", text_string(n));
    }
    if let Some(l) = &opts.location {
        sig.set("Location", text_string(l));
    }
    if let Some(c) = &opts.contact_info {
        sig.set("ContactInfo", text_string(c));
    }
    // PAdES baseline (ETSI EN 319 142-1) requires the claimed signing time in
    // `/M` and forbids the CMS `signing-time` attribute.
    let m = opts.signing_time.clone().unwrap_or_else(pdf_date_now);
    sig.set("M", Object::string_literal(m));
    Object::Dictionary(sig)
}

/// The `/FT /Sig` widget annotation referencing the signature dictionary.
fn build_widget(opts: &SignOptions, sig_id: ObjectId, ap_ref: Option<ObjectId>) -> Object {
    let mut field = Dictionary::new();
    field.set("Type", Object::Name(b"Annot".to_vec()));
    field.set("Subtype", Object::Name(b"Widget".to_vec()));
    field.set("FT", Object::Name(b"Sig".to_vec()));
    // Field name must be unique across (re-)signatures; key it to the sig id.
    field.set("T", Object::string_literal(format!("Signature{}", sig_id.0)));
    field.set("F", Object::Integer(132)); // Print | Locked
    field.set("V", Object::Reference(sig_id));

    match (&opts.appearance, ap_ref) {
        (Some(app), Some(ap_id)) => {
            field.set(
                "Rect",
                rect_array(app.x, app.y, app.x + app.width, app.y + app.height),
            );
            let mut ap = Dictionary::new();
            ap.set("N", Object::Reference(ap_id));
            field.set("AP", Object::Dictionary(ap));
        }
        _ => {
            // Invisible signature: zero-area rectangle.
            field.set("Rect", rect_array(0.0, 0.0, 0.0, 0.0));
        }
    }
    Object::Dictionary(field)
}

fn rect_array(x1: f64, y1: f64, x2: f64, y2: f64) -> Object {
    Object::Array(vec![
        Object::Real(x1 as f32),
        Object::Real(y1 as f32),
        Object::Real(x2 as f32),
        Object::Real(y2 as f32),
    ])
}

/// Object id of page `page_number` (1-based). An out-of-range page is an
/// error rather than a silent fallback to page 1.
fn nth_page_id(doc: &Document, page_number: usize) -> Result<ObjectId> {
    let pages = doc.get_pages();
    if pages.is_empty() {
        return Err(Error::Malformed("PDF has no pages".into()));
    }
    let n = u32::try_from(page_number).unwrap_or(u32::MAX);
    pages.get(&n).copied().ok_or_else(|| {
        Error::Malformed(format!(
            "page {page_number} does not exist (document has {} pages)",
            pages.len()
        ))
    })
}

/// Add the widget to the target page's `/Annots`, re-emitting only what changed.
fn apply_widget_to_page(
    doc: &Document,
    inc: &mut Incremental,
    page_id: ObjectId,
    widget_id: ObjectId,
) -> Result<()> {
    let page = doc.get_object(page_id)?.as_dict()?;
    let widget_ref = Object::Reference(widget_id);
    match page.get(b"Annots") {
        Ok(Object::Reference(r)) => {
            // Annots is its own object — modify just that array.
            let r = *r;
            let mut arr = doc.get_object(r)?.as_array()?.clone();
            arr.push(widget_ref);
            inc.add(r, Object::Array(arr));
        }
        Ok(Object::Array(a)) => {
            let mut page = page.clone();
            let mut arr = a.clone();
            arr.push(widget_ref);
            page.set("Annots", Object::Array(arr));
            inc.add(page_id, Object::Dictionary(page));
        }
        _ => {
            let mut page = page.clone();
            page.set("Annots", Object::Array(vec![widget_ref]));
            inc.add(page_id, Object::Dictionary(page));
        }
    }
    Ok(())
}

/// Register the field in `/AcroForm` (creating it if absent), re-emitting only
/// the object that actually changes. `/NeedAppearances` is cleared: a viewer
/// regenerating field appearances after signing would report the document as
/// changed.
fn apply_field_to_acroform(
    doc: &Document,
    inc: &mut Incremental,
    root_id: ObjectId,
    widget_id: ObjectId,
) -> Result<()> {
    let catalog = doc.get_object(root_id)?.as_dict()?;
    let widget_ref = Object::Reference(widget_id);

    match catalog.get(b"AcroForm") {
        Ok(Object::Reference(af)) => {
            let af = *af;
            let mut form = doc.get_object(af)?.as_dict()?.clone();
            add_field_to_form(doc, inc, &mut form, widget_ref)?;
            form.set("SigFlags", Object::Integer(3));
            form.remove(b"NeedAppearances");
            inc.add(af, Object::Dictionary(form));
        }
        Ok(Object::Dictionary(d)) => {
            let mut catalog = catalog.clone();
            let mut form = d.clone();
            add_field_to_form(doc, inc, &mut form, widget_ref)?;
            form.set("SigFlags", Object::Integer(3));
            form.remove(b"NeedAppearances");
            catalog.set("AcroForm", Object::Dictionary(form));
            inc.add(root_id, Object::Dictionary(catalog));
        }
        _ => {
            let mut catalog = catalog.clone();
            let mut form = Dictionary::new();
            form.set("Fields", Object::Array(vec![widget_ref]));
            form.set("SigFlags", Object::Integer(3));
            catalog.set("AcroForm", Object::Dictionary(form));
            inc.add(root_id, Object::Dictionary(catalog));
        }
    }
    Ok(())
}

/// Append `widget_ref` to a form's `/Fields`, handling both an inline array and
/// a referenced array object.
fn add_field_to_form(
    doc: &Document,
    inc: &mut Incremental,
    form: &mut Dictionary,
    widget_ref: Object,
) -> Result<()> {
    match form.get(b"Fields") {
        Ok(Object::Reference(fr)) => {
            let fr = *fr;
            let mut arr = doc.get_object(fr)?.as_array()?.clone();
            arr.push(widget_ref);
            inc.add(fr, Object::Array(arr));
        }
        Ok(Object::Array(a)) => {
            let mut arr = a.clone();
            arr.push(widget_ref);
            form.set("Fields", Object::Array(arr));
        }
        _ => {
            form.set("Fields", Object::Array(vec![widget_ref]));
        }
    }
    Ok(())
}

/// Find the `< 00..00 >` placeholder of the signature object that starts at
/// `obj_off`, returning the `<` and `>` indices. The search is confined to that
/// object (up to its `endobj`), so no other object's `/Contents` can be hit.
fn locate_contents_placeholder(
    buf: &[u8],
    capacity: usize,
    obj_off: usize,
) -> Result<(usize, usize)> {
    let end = obj_off
        + find_sub(&buf[obj_off..], b"endobj")
            .ok_or_else(|| Error::Malformed("signature object not terminated".into()))?;
    let obj = &buf[obj_off..end];
    let br = find_sub(obj, b"/ByteRange")
        .ok_or_else(|| Error::Malformed("/ByteRange not found".into()))?;
    let from = br
        + find_sub(&obj[br..], b"/Contents")
            .ok_or_else(|| Error::Malformed("/Contents not found".into()))?;
    let lt = from
        + find_sub(&obj[from..], b"<")
            .ok_or_else(|| Error::Malformed("Contents '<' not found".into()))?;
    let gt = lt + 1 + capacity * 2;
    if gt >= obj.len() || obj[gt] != b'>' {
        return Err(Error::Malformed(
            "Contents placeholder size mismatch".into(),
        ));
    }
    Ok((obj_off + lt, obj_off + gt))
}

/// Replace the `/ByteRange [...]` array of the signature object at `obj_off`
/// with concrete offsets, padding with spaces so the byte length is unchanged.
fn patch_byte_range(buf: &mut [u8], obj_off: usize, a: i64, b: i64, c: i64) -> Result<()> {
    let br = obj_off
        + find_sub(&buf[obj_off..], b"/ByteRange")
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
