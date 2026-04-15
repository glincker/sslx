use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::output::{box_chars, colors};

/// Extract certificate and chain from PKCS12 file
pub fn run(
    input: &str,
    password: Option<&str>,
    out_dir: &str,
    json: bool,
    no_color: bool,
) -> Result<i32> {
    let use_color = !no_color && !json && colors::should_color();

    let data = std::fs::read(input).with_context(|| format!("Failed to read: {}", input))?;
    let pass = password.unwrap_or("");

    let p12 =
        p12::PFX::parse(&data).map_err(|e| anyhow::anyhow!("Failed to parse PKCS12: {:?}", e))?;

    let bags = p12.bags(pass).map_err(|e| {
        anyhow::anyhow!(
            "Failed to decrypt PKCS12: {:?}\n\
             Hint: Check the password. Use --password to specify it.",
            e
        )
    })?;

    let out = Path::new(out_dir);
    std::fs::create_dir_all(out)
        .with_context(|| format!("Failed to create output directory: {}", out_dir))?;

    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut has_key = false;

    for bag in &bags {
        match &bag.bag {
            p12::SafeBagKind::CertBag(p12::CertBag::X509(cert_der)) => {
                certs.push(cert_der.clone());
            }
            p12::SafeBagKind::Pkcs8ShroudedKeyBag(_) => {
                has_key = true;
            }
            _ => {}
        }
    }

    if certs.is_empty() {
        bail!("No certificates found in PKCS12 file");
    }

    let mut written_files = Vec::new();

    // Write leaf cert
    if let Some(cert_der) = certs.first() {
        let cert_pem = der_to_pem(cert_der, "CERTIFICATE");
        let path = out.join("cert.pem");
        std::fs::write(&path, &cert_pem)?;
        written_files.push(("cert.pem".to_string(), "Leaf certificate".to_string()));
    }

    // Write chain (intermediate certs)
    if certs.len() > 1 {
        let mut chain_pem = String::new();
        for cert_der in &certs[1..] {
            chain_pem.push_str(&der_to_pem(cert_der, "CERTIFICATE"));
        }
        let path = out.join("chain.pem");
        std::fs::write(&path, &chain_pem)?;
        written_files.push((
            "chain.pem".to_string(),
            format!("{} intermediate certificate(s)", certs.len() - 1),
        ));
    }

    if has_key {
        written_files.push((
            "(key)".to_string(),
            "Private key detected but PKCS8 extraction requires openssl for now".to_string(),
        ));
    }

    if json {
        let output = serde_json::json!({
            "input": input,
            "output_dir": out_dir,
            "files": written_files.iter().map(|(f, d)| serde_json::json!({"file": f, "description": d})).collect::<Vec<_>>(),
            "total_certs": certs.len(),
            "has_private_key": has_key,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let icon = box_chars::CHECK;
        if use_color {
            println!(
                "\n  {}{} Extracted {} certificate(s){}\n",
                colors::BOLD_GREEN,
                icon,
                certs.len(),
                colors::RESET,
            );
        } else {
            println!("\n  {} Extracted {} certificate(s)\n", icon, certs.len(),);
        }
        for (file, desc) in &written_files {
            println!("    {:<16}{}", file, desc);
        }
        println!();
    }

    Ok(0)
}

fn der_to_pem(der_data: &[u8], label: &str) -> String {
    let b64 = base64_encode(der_data);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        result.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        result.push(if chunk.len() > 1 {
            TABLE[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            TABLE[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    result
}
