# pdf_signer

Minimal, self-contained Rust library + CLI to **digitally sign** PDF documents
with a PKCS#12 keystore and **verify** their signatures.

This is a **proof of concept** built to replace the bundled
`BatchPDFSignPortable.jar` (Java / Apache PDFBox, ~13 MB) used by the R package
[`signer`](https://github.com/StrategicProjects/signer). The goal is to drop the
Java runtime dependency and the binary blob, enabling a clean, CRAN-friendly
native backend.

## Status: the PoC works end to end

A signed PDF produced here is validated **independently by Poppler's `pdfsig`**:

```
$ cargo run --example gen_assets
$ cargo run --bin pdf_signer -- sign sample.pdf signed.pdf keystore.p12 password "Reason"
$ cargo run --bin pdf_signer -- verify signed.pdf      # our own verifier
$ pdfsig signed.pdf                                     # third-party cross-check
  - Signature Type: adbe.pkcs7.detached
  - Signing Hash Algorithm: SHA-256
  - Total document signed
  - Signature Validation: Signature is Valid.
```

`cargo test` covers the round trip, tamper detection, and the unsigned case.

## How it works

1. **PDF structure** (`lopdf`): add an AcroForm signature field + a `/Sig`
   dictionary with `/SubFilter /adbe.pkcs7.detached`, a `/ByteRange` placeholder
   and a zero-filled `/Contents` hex placeholder.
2. **Byte surgery**: serialize once, locate the placeholder, compute the real
   `/ByteRange` and patch it length-preservingly.
3. **CMS signature** (`openssl`): load the PKCS#12, produce a detached PKCS#7
   (CMS) signature over the byte range, hex-encode it into `/Contents`.
4. **Verify**: re-derive the signed byte range from the file, slice the CMS DER
   out of the placeholder, and validate it cryptographically.

## API

```rust
use pdf_signer::{sign_pdf_file, verify_pdf_file, SignOptions};

sign_pdf_file("in.pdf", "out.pdf", "keystore.p12", "password", &SignOptions {
    reason: Some("Signed by Org".into()),
    ..Default::default()
})?;

let report = verify_pdf_file("out.pdf")?;
assert!(report.all_valid());
```

## Known limitations (PoC scope — see roadmap)

- **Invisible signature only** — no visual appearance stream yet (the `signtext`
  / rectangle / validation-link box from the R package is not rendered).
- **Full-rewrite save**, not an incremental update. Fine for a first signature;
  must become an append-only incremental update before multi-signature support.
- **OpenSSL backend.** Uses the system OpenSSL via the `openssl` crate. For a
  vendored, CRAN-friendly build this should move to a pure-Rust RustCrypto
  stack (`cms`, `pkcs12`) — the single biggest item before publishing.
- **No PAdES-LTV / timestamps (RFC 3161)** and no chain/revocation checking on
  verify (`NOVERIFY`); signer trust is reported but not enforced.
- Single signature parsed on verify; AcroForm is overwritten rather than merged.

## Roadmap to replace the JAR in `signer`

1. Visual appearance stream (port the `signtext` box + validation link).
2. Incremental-update save for multi-signature / re-signing.
3. Swap OpenSSL → RustCrypto, then vendor crates for an R package build
   (`SystemRequirements: Cargo, rustc`).
4. Expose to R: either a thin CLI invoked via `system2`, or a native binding
   (e.g. via `extendr`) compiled into the package.
5. PAdES baseline (B-T) with RFC 3161 timestamps if legal validity requires it.

## License

GPL-3.0-or-later, matching the `signer` package.
