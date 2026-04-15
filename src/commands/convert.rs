use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::output::{box_chars, colors};

/// Convert between certificate formats (PEM, DER, PKCS12)
pub fn run(
    input: &str,
    to_format: &str,
    key_path: Option<&str>,
    password: Option<&str>,
    output_path: Option<&str>,
    json: bool,
    no_color: bool,
) -> Result<i32> {
    let use_color = !no_color && !json && colors::should_color();

    let data = std::fs::read(input).with_context(|| format!("Failed to read: {}", input))?;

    let from_format = detect_format(&data, input);
    let to = to_format.to_lowercase();

    let (out_data, out_ext) = match (from_format.as_str(), to.as_str()) {
        ("pem", "der") => {
            let der = pem_to_der_bytes(&data)?;
            (der, "der")
        }
        ("der", "pem") => {
            let pem = der_to_pem(&data, "CERTIFICATE");
            (pem.into_bytes(), "pem")
        }
        ("pem", "pkcs12") | ("pem", "p12") | ("pem", "pfx") => {
            let key_file = key_path.context(
                "Private key required for PKCS12 conversion.\n\
                 Usage: sslx convert cert.pem --to pkcs12 --key key.pem",
            )?;
            let key_data = std::fs::read(key_file)
                .with_context(|| format!("Failed to read key: {}", key_file))?;
            let pass = password.unwrap_or("");
            let p12 = build_pkcs12(&data, &key_data, pass)?;
            (p12, "p12")
        }
        ("pkcs12", "pem") | ("p12", "pem") | ("pfx", "pem") => {
            let pass = password.unwrap_or("");
            let pem = pkcs12_to_pem(&data, pass)?;
            (pem.into_bytes(), "pem")
        }
        (from, to_fmt) if from == to_fmt => {
            bail!("Input is already in {} format", to_fmt.to_uppercase());
        }
        (from, to_fmt) => {
            bail!(
                "Conversion from {} to {} is not supported.\n\
                 Supported: PEM ↔ DER, PEM ↔ PKCS12",
                from.to_uppercase(),
                to_fmt.to_uppercase()
            );
        }
    };

    // Determine output path
    let out_path = if let Some(p) = output_path {
        p.to_string()
    } else {
        let stem = Path::new(input)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("output");
        format!("{}.{}", stem, out_ext)
    };

    std::fs::write(&out_path, &out_data)
        .with_context(|| format!("Failed to write: {}", out_path))?;

    if json {
        let output = serde_json::json!({
            "input": input,
            "input_format": from_format,
            "output": out_path,
            "output_format": to,
            "size_bytes": out_data.len(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let icon = box_chars::CHECK;
        if use_color {
            println!(
                "\n  {}{} Converted{} {} → {}\n",
                colors::BOLD_GREEN,
                icon,
                colors::RESET,
                from_format.to_uppercase(),
                to.to_uppercase(),
            );
        } else {
            println!(
                "\n  {} Converted {} → {}\n",
                icon,
                from_format.to_uppercase(),
                to.to_uppercase(),
            );
        }
        println!("    Input:   {}", input);
        println!("    Output:  {} ({} bytes)", out_path, out_data.len());
        println!();
    }

    Ok(0)
}

fn detect_format(data: &[u8], filename: &str) -> String {
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if data.starts_with(b"-----BEGIN ") {
        return "pem".to_string();
    }
    match ext.as_str() {
        "p12" | "pfx" => "pkcs12".to_string(),
        "der" => "der".to_string(),
        _ if !data.is_empty() && data[0] == 0x30 => "der".to_string(),
        _ => "unknown".to_string(),
    }
}

fn pem_to_der_bytes(pem_data: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem_data).context("Invalid UTF-8 in PEM file")?;
    let mut base64_buf = String::new();
    let mut in_block = false;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN ") {
            in_block = true;
            base64_buf.clear();
        } else if line.starts_with("-----END ") {
            if in_block {
                return crate::cert::parser::base64_decode_str(&base64_buf);
            }
        } else if in_block {
            base64_buf.push_str(line);
        }
    }

    bail!("No PEM block found in input")
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
        if chunk.len() > 1 {
            result.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

fn build_pkcs12(cert_pem: &[u8], key_pem: &[u8], _password: &str) -> Result<Vec<u8>> {
    // For now, use p12 crate for PKCS12 building
    let _cert_der = pem_to_der_bytes(cert_pem)?;
    let _key_der = pem_to_der_bytes(key_pem)?;

    // p12 crate build
    bail!(
        "PKCS12 export is not yet implemented.\n\
         Hint: Use `openssl pkcs12 -export` for now. Coming in sslx v0.3."
    )
}

fn pkcs12_to_pem(data: &[u8], password: &str) -> Result<String> {
    let p12 =
        p12::PFX::parse(data).map_err(|e| anyhow::anyhow!("Failed to parse PKCS12: {:?}", e))?;

    let bags = p12
        .bags(password)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt PKCS12 (wrong password?): {:?}", e))?;

    let mut pem_output = String::new();

    for bag in &bags {
        if let p12::SafeBagKind::CertBag(p12::CertBag::X509(cert_der)) = &bag.bag {
            pem_output.push_str(&der_to_pem(cert_der, "CERTIFICATE"));
        }
    }

    if pem_output.is_empty() {
        bail!("No certificates or keys found in PKCS12 file");
    }

    Ok(pem_output)
}
