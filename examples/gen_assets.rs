//! Generate reproducible demo assets: `sample.pdf` and `keystore.p12`.
//!
//! ```sh
//! cargo run --example gen_assets
//! cargo run --bin pdf_signer -- sign sample.pdf signed.pdf keystore.p12 password
//! cargo run --bin pdf_signer -- verify signed.pdf
//! ```

use pdf_signer::testkit::{sample_pdf, self_signed_p12};

fn main() -> std::io::Result<()> {
    std::fs::write("sample.pdf", sample_pdf())?;
    std::fs::write("keystore.p12", self_signed_p12("password"))?;
    println!("wrote sample.pdf and keystore.p12 (keystore password: 'password')");
    Ok(())
}
