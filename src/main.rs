//! Thin CLI around the `pdf_signer` library.
//!
//! ```text
//! pdf_signer sign   <input.pdf> <output.pdf> <keystore.p12> <password> [reason]
//! pdf_signer verify <signed.pdf>
//! ```

use std::process::ExitCode;

use pdf_signer::{sign_pdf_file, verify_pdf_file, Appearance, PadesLevel, SignOptions};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("sign") => cmd_sign(&args),
        Some("verify") => cmd_verify(&args),
        _ => {
            eprintln!("usage:");
            eprintln!("  pdf_signer sign   <input.pdf> <output.pdf> <keystore.p12> <password> [reason]");
            eprintln!("  pdf_signer verify <signed.pdf>");
            ExitCode::from(2)
        }
    }
}

fn cmd_sign(args: &[String]) -> ExitCode {
    if args.len() < 6 {
        eprintln!("sign: need <input.pdf> <output.pdf> <keystore.p12> <password> [reason] [tsa_url] [bb|bt|blt|blta]");
        return ExitCode::from(2);
    }
    let reason = args.get(6).cloned();
    let box_text = format!(
        "{}\nAssinado digitalmente por pdf_signer PoC (StrategicProjects).\nValidar em: apps.example.org/validate",
        reason.as_deref().unwrap_or("Documento assinado digitalmente")
    );
    let level = match args.get(8).map(String::as_str) {
        Some("bt") => PadesLevel::Bt,
        Some("blt") => PadesLevel::Blt,
        Some("blta") => PadesLevel::Blta,
        _ => PadesLevel::Bb,
    };
    let opts = SignOptions {
        reason,
        name: Some("pdf_signer PoC".to_string()),
        tsa_url: args.get(7).cloned(), // optional RFC 3161 TSA http:// URL
        pades_level: level,
        appearance: Some(Appearance {
            page: 1,
            x: 36.0,
            y: 36.0,
            width: 320.0,
            height: 64.0,
            font_size: 8.0,
            text: box_text,
            border: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    match sign_pdf_file(&args[2], &args[3], &args[4], &args[5], &opts) {
        Ok(()) => {
            println!("signed: {} -> {}", args[2], args[3]);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_verify(args: &[String]) -> ExitCode {
    if args.len() < 3 {
        eprintln!("verify: need <signed.pdf>");
        return ExitCode::from(2);
    }
    match verify_pdf_file(&args[2]) {
        Ok(report) => {
            if report.signatures.is_empty() {
                println!("no signatures found");
                return ExitCode::FAILURE;
            }
            for (i, s) in report.signatures.iter().enumerate() {
                println!("signature #{}:", i + 1);
                println!("  valid:                 {}", s.valid);
                println!("  signer:                {}", s.signer.as_deref().unwrap_or("-"));
                println!("  byte_range:            {:?}", s.byte_range);
                println!("  signed_len:            {} bytes", s.signed_len);
                println!("  covers_whole_document: {}", s.covers_whole_document);
                println!("  detail:                {}", s.detail);
            }
            if report.all_valid() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
