//! Incremental update writer.
//!
//! Instead of re-serializing the whole document (which would invalidate any
//! pre-existing signature), an incremental update keeps the original bytes
//! **verbatim** and appends:
//!   * the new / modified objects,
//!   * a fresh cross-reference table listing only those objects,
//!   * a trailer whose `/Prev` chains back to the previous xref and that
//!     carries the previous trailer's entries (`/Info`, `/ID`, …) forward.
//!
//! This is what makes multi-signature work: signing again only appends, so
//! earlier signatures keep covering an unchanged byte range.
//!
//! Offsets written into the new cross-reference section are relative to the
//! `%PDF-` header (PDF 32000-1 §7.5.2), which matters for files that carry
//! junk bytes before the header; `/ByteRange` offsets, by contrast, are always
//! absolute file offsets and are handled by the signer.

use std::collections::BTreeMap;

use lopdf::{Dictionary, Object, ObjectId, Stream, StringFormat};

use crate::util::find_sub;

/// Accumulates the objects to append and renders the updated file.
pub(crate) struct Incremental<'a> {
    original: &'a [u8],
    /// Offset of `%PDF-` in `original` (0 for a well-formed file).
    base: usize,
    objects: BTreeMap<u32, (u16, Object)>,
}

/// The rendered file plus the absolute offset at which each appended object's
/// `N G obj` header starts, so callers can locate placeholders inside a
/// specific object instead of searching the bytes.
pub(crate) struct Rendered {
    pub bytes: Vec<u8>,
    pub offsets: BTreeMap<u32, usize>,
}

/// One appended object for the cross-reference section: `(id, generation,
/// absolute offset)`.
type XrefEntry = (u32, u16, usize);

/// Trailer keys that belong to a specific cross-reference section (or to an
/// xref *stream* object) and must not be carried into the next trailer.
const SECTION_KEYS: &[&[u8]] = &[
    b"Size", b"Prev", b"XRefStm", b"Type", b"W", b"Index", b"Filter", b"Length",
    b"DecodeParms", b"DL", b"F", b"FFilter", b"FDecodeParms",
];

impl<'a> Incremental<'a> {
    pub(crate) fn new(original: &'a [u8]) -> Self {
        Self {
            original,
            base: header_offset(original),
            objects: BTreeMap::new(),
        }
    }

    /// Queue an object (new or modified) for the update section.
    pub(crate) fn add(&mut self, id: ObjectId, obj: Object) {
        self.objects.insert(id.0, (id.1, obj));
    }

    /// Render `original + appended update`. `size` is the new `/Size`,
    /// `root` the catalog id, `prev` the previous `startxref` offset, and
    /// `trailer` the previous trailer whose document-level entries (`/Info`,
    /// `/ID`, …) are carried forward. Emits a cross-reference **stream** when
    /// the original uses one, otherwise a traditional cross-reference **table**
    /// — matching the source's convention.
    pub(crate) fn render(
        &self,
        size: u32,
        root: ObjectId,
        prev: usize,
        trailer: &Dictionary,
    ) -> Rendered {
        let extra = carried_trailer(trailer);
        if uses_xref_stream(self.original, self.base) {
            self.render_xref_stream(size, root, prev, &extra)
        } else {
            self.render_xref_table(size, root, prev, &extra)
        }
    }

    /// Emit the queued objects, returning the buffer, the appended entries
    /// `(id, gen, absolute offset)` and the absolute offsets map.
    fn emit_objects(&self) -> (Vec<u8>, Vec<XrefEntry>, BTreeMap<u32, usize>) {
        let mut out = self.original.to_vec();
        if !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        let mut entries: Vec<XrefEntry> = Vec::with_capacity(self.objects.len() + 1);
        let mut offsets = BTreeMap::new();
        for (&id, (gen, obj)) in &self.objects {
            let off = out.len();
            out.extend_from_slice(format!("{} {} obj\n", id, gen).as_bytes());
            write_object(&mut out, obj);
            out.extend_from_slice(b"\nendobj\n");
            entries.push((id, *gen, off));
            offsets.insert(id, off);
        }
        (out, entries, offsets)
    }

    /// Traditional cross-reference table incremental update.
    fn render_xref_table(
        &self,
        size: u32,
        root: ObjectId,
        prev: usize,
        extra: &Dictionary,
    ) -> Rendered {
        let (mut out, entries, offsets) = self.emit_objects();

        // Cross-reference table (entries are already sorted by id); offsets are
        // relative to the %PDF- header.
        let xref_off = out.len() - self.base;
        out.extend_from_slice(b"xref\n");
        let mut i = 0;
        while i < entries.len() {
            let mut j = i;
            while j + 1 < entries.len() && entries[j + 1].0 == entries[j].0 + 1 {
                j += 1;
            }
            out.extend_from_slice(format!("{} {}\n", entries[i].0, j - i + 1).as_bytes());
            for e in &entries[i..=j] {
                // Each entry is exactly 20 bytes: "%010d %05d n\r\n".
                out.extend_from_slice(
                    format!("{:010} {:05} n\r\n", e.2 - self.base, e.1).as_bytes(),
                );
            }
            i = j + 1;
        }

        // Trailer + startxref.
        let mut trailer = Dictionary::new();
        trailer.set("Size", Object::Integer(size as i64));
        trailer.set("Root", Object::Reference(root));
        trailer.set("Prev", Object::Integer(prev as i64));
        for (k, v) in extra.iter() {
            trailer.set(k.clone(), v.clone());
        }
        out.extend_from_slice(b"trailer\n");
        write_dict(&mut out, &trailer);
        out.extend_from_slice(b"\nstartxref\n");
        out.extend_from_slice(format!("{}\n%%EOF\n", xref_off).as_bytes());
        Rendered { bytes: out, offsets }
    }

    /// Cross-reference **stream** incremental update (PDF 1.5+). The xref is a
    /// `/Type /XRef` stream object that also indexes itself.
    fn render_xref_stream(
        &self,
        size: u32,
        root: ObjectId,
        prev: usize,
        extra: &Dictionary,
    ) -> Rendered {
        let (mut out, mut entries, offsets) = self.emit_objects();

        // The xref stream is itself an object; it indexes itself.
        let xref_id = size; // next free id
        let xref_off = out.len();
        entries.push((xref_id, 0, xref_off));
        entries.sort_by_key(|e| e.0);

        // Field widths W = [1, n, 2], with the offset width chosen to fit the
        // largest offset (4 bytes below 4 GiB, 8 above).
        let max_off = entries.iter().map(|e| e.2 - self.base).max().unwrap_or(0);
        let off_w: usize = if max_off > u32::MAX as usize { 8 } else { 4 };
        let mut data = Vec::with_capacity(entries.len() * (3 + off_w));
        for (_, gen, off) in &entries {
            data.push(1u8); // type 1: in-use object
            let rel = (*off - self.base) as u64;
            data.extend_from_slice(&rel.to_be_bytes()[8 - off_w..]);
            data.extend_from_slice(&gen.to_be_bytes());
        }
        let compressed = zlib_compress(&data);

        // /Index subsections for the (sorted) object ids.
        let mut index = Vec::new();
        let mut i = 0;
        while i < entries.len() {
            let mut j = i;
            while j + 1 < entries.len() && entries[j + 1].0 == entries[j].0 + 1 {
                j += 1;
            }
            index.push(Object::Integer(entries[i].0 as i64));
            index.push(Object::Integer((j - i + 1) as i64));
            i = j + 1;
        }

        let mut dict = Dictionary::new();
        dict.set("Type", Object::Name(b"XRef".to_vec()));
        dict.set("Size", Object::Integer(xref_id as i64 + 1));
        dict.set("Root", Object::Reference(root));
        dict.set("Prev", Object::Integer(prev as i64));
        dict.set(
            "W",
            Object::Array(vec![
                Object::Integer(1),
                Object::Integer(off_w as i64),
                Object::Integer(2),
            ]),
        );
        dict.set("Index", Object::Array(index));
        for (k, v) in extra.iter() {
            dict.set(k.clone(), v.clone());
        }
        dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        dict.set("Length", Object::Integer(compressed.len() as i64));

        out.extend_from_slice(format!("{} 0 obj\n", xref_id).as_bytes());
        write_dict(&mut out, &dict);
        out.extend_from_slice(b"\nstream\n");
        out.extend_from_slice(&compressed);
        out.extend_from_slice(b"\nendstream\nendobj\n");

        out.extend_from_slice(b"startxref\n");
        out.extend_from_slice(format!("{}\n%%EOF\n", xref_off - self.base).as_bytes());
        Rendered { bytes: out, offsets }
    }
}

/// The entries of the previous trailer worth carrying into the new one:
/// everything but the per-section keys (and never `/Encrypt`, which the signer
/// refuses up front).
fn carried_trailer(trailer: &Dictionary) -> Dictionary {
    let mut extra = Dictionary::new();
    for (k, v) in trailer.iter() {
        if SECTION_KEYS.contains(&k.as_slice()) || k == b"Root" || k == b"Encrypt" {
            continue;
        }
        extra.set(k.clone(), v.clone());
    }
    extra
}

/// Offset of the `%PDF-` header within the first 1024 bytes (readers tolerate
/// leading junk, and file offsets are then relative to the header). 0 when the
/// header is missing or at the start.
pub(crate) fn header_offset(buf: &[u8]) -> usize {
    let window = &buf[..buf.len().min(1024)];
    find_sub(window, b"%PDF-").unwrap_or(0)
}

/// True if the file's most recent cross-reference is a stream (not an `xref`
/// table), i.e. `startxref` points at an object rather than the `xref` keyword.
fn uses_xref_stream(buf: &[u8], base: usize) -> bool {
    let Some(off) = last_startxref(buf) else {
        return false;
    };
    let mut i = off + base;
    while i < buf.len() && buf[i].is_ascii_whitespace() {
        i += 1;
    }
    i < buf.len() && !buf[i..].starts_with(b"xref")
}

/// Zlib-compress (PDF `FlateDecode`).
pub(crate) fn zlib_compress(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("zlib write");
    encoder.finish().expect("zlib finish")
}

/// Value of the most recent `startxref` in `buf` (the previous xref offset,
/// relative to the `%PDF-` header as the file states it).
pub(crate) fn last_startxref(buf: &[u8]) -> Option<usize> {
    let needle = b"startxref";
    let pos = (0..=buf.len().saturating_sub(needle.len()))
        .rev()
        .find(|&i| &buf[i..i + needle.len()] == needle)?;
    let mut i = pos + needle.len();
    while i < buf.len() && buf[i].is_ascii_whitespace() {
        i += 1;
    }
    let mut n = 0usize;
    let mut any = false;
    while i < buf.len() && buf[i].is_ascii_digit() {
        n = n.checked_mul(10)?.checked_add((buf[i] - b'0') as usize)?;
        i += 1;
        any = true;
    }
    any.then_some(n)
}

// --- a minimal, byte-exact PDF object serializer ------------------------------

fn write_object(out: &mut Vec<u8>, obj: &Object) {
    match obj {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Object::Integer(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Object::Real(r) => out.extend_from_slice(fmt_real(*r).as_bytes()),
        Object::Name(n) => write_name(out, n),
        Object::String(s, fmt) => write_string(out, s, *fmt),
        Object::Reference(id) => {
            out.extend_from_slice(format!("{} {} R", id.0, id.1).as_bytes())
        }
        Object::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_object(out, e);
            }
            out.push(b']');
        }
        Object::Dictionary(d) => write_dict(out, d),
        Object::Stream(s) => write_stream(out, s),
    }
}

fn write_dict(out: &mut Vec<u8>, d: &Dictionary) {
    out.extend_from_slice(b"<< ");
    for (k, v) in d.iter() {
        write_name(out, k);
        out.push(b' ');
        write_object(out, v);
        out.push(b' ');
    }
    out.extend_from_slice(b">>");
}

fn write_stream(out: &mut Vec<u8>, s: &Stream) {
    let mut dict = s.dict.clone();
    dict.set("Length", Object::Integer(s.content.len() as i64));
    write_dict(out, &dict);
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(&s.content);
    out.extend_from_slice(b"\nendstream");
}

fn write_name(out: &mut Vec<u8>, name: &[u8]) {
    out.push(b'/');
    for &b in name {
        let regular = (0x21..0x7f).contains(&b)
            && !matches!(
                b,
                b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%' | b'#'
            );
        if regular {
            out.push(b);
        } else {
            out.extend_from_slice(format!("#{:02X}", b).as_bytes());
        }
    }
}

fn write_string(out: &mut Vec<u8>, s: &[u8], fmt: StringFormat) {
    match fmt {
        StringFormat::Hexadecimal => {
            out.push(b'<');
            for &b in s {
                out.extend_from_slice(format!("{:02x}", b).as_bytes());
            }
            out.push(b'>');
        }
        StringFormat::Literal => {
            out.push(b'(');
            for &b in s {
                match b {
                    b'(' | b')' | b'\\' => {
                        out.push(b'\\');
                        out.push(b);
                    }
                    b'\n' => out.extend_from_slice(b"\\n"),
                    b'\r' => out.extend_from_slice(b"\\r"),
                    _ => out.push(b),
                }
            }
            out.push(b')');
        }
    }
}

/// Format a real without scientific notation (PDF forbids it). Non-finite
/// values are rejected upstream (`sign.rs` validates appearance geometry);
/// here they degrade to `0` rather than emitting an invalid token.
fn fmt_real(r: f32) -> String {
    if !r.is_finite() {
        return "0".to_string();
    }
    if r == r.trunc() {
        format!("{}", r as i64)
    } else {
        let s = format!("{r}");
        if s.contains(['e', 'E']) {
            format!("{r:.6}")
        } else {
            s
        }
    }
}

/// Encode text for a PDF **text string** entry (`/Reason`, `/Name`, `/T`, …):
/// plain ASCII is written as a literal string; anything else as UTF-16BE with
/// the `FE FF` byte-order mark (PDF 32000-1 §7.9.2.2), so accented and
/// non-Latin characters survive every viewer instead of being misread as
/// PDFDocEncoding bytes.
pub(crate) fn text_string(s: &str) -> Object {
    if s.is_ascii() {
        Object::String(s.as_bytes().to_vec(), StringFormat::Literal)
    } else {
        let mut bytes = vec![0xFE, 0xFF];
        for unit in s.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        Object::String(bytes, StringFormat::Hexadecimal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_string_uses_utf16_for_non_ascii() {
        assert!(matches!(text_string("Approved"), Object::String(_, StringFormat::Literal)));
        match text_string("Aprovação") {
            Object::String(b, StringFormat::Hexadecimal) => {
                assert_eq!(&b[..2], &[0xFE, 0xFF]);
                let units: Vec<u16> = b[2..]
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                assert_eq!(String::from_utf16(&units).unwrap(), "Aprovação");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn header_offset_tolerates_leading_junk() {
        assert_eq!(header_offset(b"%PDF-1.7\n"), 0);
        assert_eq!(header_offset(b"JUNK\n%PDF-1.7\n"), 5);
    }

    #[test]
    fn carried_trailer_drops_section_keys() {
        let mut t = Dictionary::new();
        t.set("Size", Object::Integer(9));
        t.set("Root", Object::Reference((1, 0)));
        t.set("Info", Object::Reference((2, 0)));
        t.set("Prev", Object::Integer(100));
        t.set("Encrypt", Object::Reference((3, 0)));
        t.set("W", Object::Array(vec![]));
        let c = carried_trailer(&t);
        assert!(c.has(b"Info"));
        for k in ["Size", "Root", "Prev", "Encrypt", "W"] {
            assert!(!c.has(k.as_bytes()), "{k} must not be carried");
        }
    }
}
