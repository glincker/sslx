use anyhow::{bail, Result};
use std::io::Read;
use crate::cert::parser::{
    parse_cert_data, parse_cert_file,
    verbose_parse_cert_data, verbose_parse_cert_file
};
use crate::output::colors;
use crate::output::json::JsonCert;
use crate::output::json::JsonCertOutput;
use crate::output::terminal;

pub fn run(path: &str, json: bool, verbose: bool, no_color: bool) -> Result<i32> {
    if !verbose {
        let certs = if path == "-" {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            parse_cert_data(&buf)?
        } else {
            parse_cert_file(path)?
        };
        run_certs(&certs, json, no_color)
    } else {
        let certs = if path == "-" {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            verbose_parse_cert_data(&buf)?
        } else {
            verbose_parse_cert_file(path)?
        };
        verbose_run_certs(&certs, json, no_color)
    }
}

/// Render already-parsed certs (used by `decode` to avoid re-reading the source).
pub fn run_certs(certs: &[crate::cert::CertInfo], json: bool, no_color: bool) -> Result<i32> {
    let use_color = !no_color && !json && colors::should_color();

    if json {
        let output = JsonCertOutput {
            certificates: certs.iter().map(JsonCert::from).collect(),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(exit_code_for_certs(certs));
    }
    let total = certs.len();
    for (i, cert) in certs.iter().enumerate() {
        println!("{}", terminal::render_cert(cert, i, total, use_color));
        if i < total - 1 {
            println!("{}", terminal::render_chain_arrow(use_color));
        }
    }

    Ok(exit_code_for_certs(certs))
}

fn exit_code_for_certs(certs: &[crate::cert::CertInfo]) -> i32 {
    if certs.iter().any(|c| c.is_expired()) {
        1 // expired
    } else {
        0 // valid
    }
}

pub fn verbose_run_certs(certs: &[crate::cert::VerboseCert], json: bool, no_color: bool) -> Result<i32> {
    if json {
        bail!("Verbose json output not yet supported")
    }

    for c in certs.iter() {
        for e in c.extensions.iter() {
            println!("--{}--", e.0);
            for s in e.1 {
                println!("{}: {}", s.0, s.1);
            }
        }
    }

    Ok(exit_code_for_verbose_certs(certs))
}

// todo Use traits for this instead
fn exit_code_for_verbose_certs(certs: &[crate::cert::VerboseCert]) -> i32 {
    if certs.iter().any(|c| c.is_expired()) {
        1 // expired
    } else {
        0 // valid
    }
}
