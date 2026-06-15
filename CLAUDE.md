# pdf_signer — guidance for Claude

Pure-Rust library **+ CLI** to digitally sign (PAdES) and verify PDF documents.
This crate is the **engine** of a 3-package ecosystem (see "Consumers" below).

## What it is
- PAdES **B-B → B-LTA** (CAdES `signing-certificate-v2`, RFC 3161 signature &
  document timestamps, `/DSS` with chain + CRLs + OCSP).
- Keys: RSA, ECDSA (P-256/P-384), Ed25519. Revocation: CRL + OCSP.
- **RFC 5280 path validation** (name constraints + certificate-policy engine)
  **validated against the NIST PKITS suite** (42/42 policy + 38/38 name-constraint).
- 100% pure Rust (RustCrypto) — **no OpenSSL, no Java, no system C libs**.
  Optional `https` feature (ureq/rustls) for TSA/CRL/OCSP over HTTPS.

## Layout (`src/`)
`sign`, `verify`, `trust` (RFC 5280), `policy` (PKITS engine), `dss`, `tsa`,
`crypto` (CMS/PKCS#7), `appearance` (embedded TrueType fonts + PNG/JPEG logos),
`incremental` (xref table **and** xref-stream), `util`, `testkit`, `main.rs` (CLI).

## Build / test
```sh
cargo build --all-features
cargo test --all-features
cargo clippy --all-features --all-targets
# NIST PKITS conformance (download PKITS data first):
PKITS_DIR=/path/to/pkits cargo test --test pkits -- --ignored
```

## Consumers — keep in sync when the public API changes
- **R**: `pdfsigner` (extendr) — bundles a COPY of this crate at
  `pdfsigner/src/rust/pdf_signer/`. Re-sync + re-vendor on every release.
- **Python**: `pdfsignerpy` (PyO3) — depends on this crate as a **git dep pinned
  to a tag** (currently `v0.1.7`). Bump the tag there after a release here.

## Release
Tag `vX.Y.Z` + GitHub release. Current: **v0.1.7**. Bump `version` in `Cargo.toml`.

## Conventions
- Be **honest about scope** in README/release notes (this is how the PKITS caveat
  was handled before it was earned).
- Keep the README architecture diagram (`docs/architecture.svg`) in step with the
  R/Python ones.
