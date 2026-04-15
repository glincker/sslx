use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::output::util::{der_to_pem, print_status};
use crate::output::{box_chars, colors};

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
        let msg = format!("Extracted {} certificate(s)", certs.len());
        print_status(box_chars::CHECK, &msg, colors::BOLD_GREEN, use_color);
        for (file, desc) in &written_files {
            println!("    {:<16}{}", file, desc);
        }
        println!();
    }

    Ok(0)
}
