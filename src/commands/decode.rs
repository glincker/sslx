use anyhow::{Context, Result};
use std::io::Read;

use crate::output::{box_chars, colors};

pub fn run(input: &str, json: bool, no_color: bool) -> Result<i32> {
    let use_color = !no_color && !json && colors::should_color();

    // Check if input is stdin, a file path, or inline string
    let (data, source) = if input == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        (buf, "<stdin>".to_string())
    } else if std::path::Path::new(input).exists() {
        let data = std::fs::read(input).with_context(|| format!("Failed to read: {}", input))?;
        (data, input.to_string())
    } else {
        // Treat as inline string (could be base64/JWT)
        (input.as_bytes().to_vec(), "inline".to_string())
    };

    let text = String::from_utf8_lossy(&data);

    // Try to detect the type
    if text.starts_with("-----BEGIN CERTIFICATE") {
        return decode_as_cert(&data, &source, json, no_color, use_color, "PEM Certificate");
    }

    if text.starts_with("-----BEGIN CERTIFICATE REQUEST")
        || text.starts_with("-----BEGIN NEW CERTIFICATE REQUEST")
    {
        return decode_as_csr(&text, json, use_color);
    }

    if text.starts_with("-----BEGIN PRIVATE KEY")
        || text.starts_with("-----BEGIN RSA PRIVATE KEY")
        || text.starts_with("-----BEGIN EC PRIVATE KEY")
    {
        return decode_as_key(&text, json, use_color);
    }

    if text.starts_with("-----BEGIN PUBLIC KEY") {
        decode_as_public_key(&text, json, use_color)?;
        return Ok(0);
    }

    // JWT detection (three base64url segments separated by dots)
    let trimmed = text.trim();
    if trimmed.matches('.').count() == 2
        && trimmed.split('.').all(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '=')
        })
    {
        return decode_jwt(trimmed, json, use_color);
    }

    // DER certificate
    if !data.is_empty() && data[0] == 0x30 && source != "inline" {
        return decode_as_cert(&data, &source, json, no_color, use_color, "DER Certificate");
    }

    if json {
        let output = serde_json::json!({
            "detected": "unknown",
            "source": source,
            "error": "Could not detect format",
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let icon = box_chars::CROSS;
        if use_color {
            println!(
                "\n  {}{} Could not detect format{}\n",
                colors::BOLD_RED,
                icon,
                colors::RESET,
            );
        } else {
            println!("\n  {} Could not detect format\n", icon);
        }
        println!("    Supported: PEM/DER certificates, CSRs, private keys, public keys, JWTs");
        println!();
    }

    Ok(5)
}

fn decode_as_cert(
    data: &[u8],
    source: &str,
    json: bool,
    no_color: bool,
    use_color: bool,
    label: &str,
) -> Result<i32> {
    if use_color {
        println!("\n  {}Detected:{} {}\n", colors::BOLD, colors::RESET, label,);
    } else {
        println!("\n  Detected: {}\n", label);
    }
    let certs = crate::cert::parser::parse_cert_data_from(data, source)?;
    crate::commands::inspect::run_certs(&certs, json, no_color)
}

fn decode_as_csr(text: &str, json: bool, use_color: bool) -> Result<i32> {
    if json {
        let output = serde_json::json!({
            "detected": "Certificate Signing Request (CSR)",
            "format": "PEM",
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let icon = box_chars::CHECK;
        if use_color {
            println!(
                "\n  {}{} Detected:{} Certificate Signing Request (CSR)\n",
                colors::BOLD_GREEN,
                icon,
                colors::RESET,
            );
        } else {
            println!("\n  {} Detected: Certificate Signing Request (CSR)\n", icon);
        }

        // Count lines to show size
        let line_count = text.lines().filter(|l| !l.starts_with("-----")).count();
        println!("    Format:  PEM");
        println!("    Size:    ~{} bytes encoded", line_count * 64);
        println!();
    }
    Ok(0)
}

fn decode_as_key(text: &str, json: bool, use_color: bool) -> Result<i32> {
    let key_type = if text.contains("RSA PRIVATE KEY") {
        "RSA Private Key (PKCS#1)"
    } else if text.contains("EC PRIVATE KEY") {
        "EC Private Key (SEC1)"
    } else {
        "Private Key (PKCS#8)"
    };

    if json {
        let output = serde_json::json!({
            "detected": key_type,
            "format": "PEM",
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let icon = box_chars::CHECK;
        if use_color {
            println!(
                "\n  {}{} Detected:{} {}\n",
                colors::BOLD_GREEN,
                icon,
                colors::RESET,
                key_type,
            );
        } else {
            println!("\n  {} Detected: {}\n", icon, key_type);
        }
        println!("    Format:  PEM");
        println!();
    }
    Ok(0)
}

fn decode_as_public_key(_text: &str, json: bool, use_color: bool) -> Result<()> {
    if json {
        let output = serde_json::json!({ "detected": "Public Key", "format": "PEM" });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let icon = box_chars::CHECK;
        if use_color {
            println!(
                "\n  {}{} Detected:{} Public Key (PEM)\n",
                colors::BOLD_GREEN,
                icon,
                colors::RESET
            );
        } else {
            println!("\n  {} Detected: Public Key (PEM)\n", icon);
        }
    }
    Ok(())
}

fn decode_jwt(token: &str, json: bool, use_color: bool) -> Result<i32> {
    let parts: Vec<&str> = token.split('.').collect();

    let header = base64url_decode(parts[0])?;
    let payload = base64url_decode(parts[1])?;

    let header_json: serde_json::Value =
        serde_json::from_str(&header).unwrap_or(serde_json::Value::Null);
    let payload_json: serde_json::Value =
        serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null);

    if json {
        let output = serde_json::json!({
            "detected": "JWT",
            "header": header_json,
            "payload": payload_json,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let icon = box_chars::CHECK;
        if use_color {
            println!(
                "\n  {}{} Detected:{} JSON Web Token (JWT)\n",
                colors::BOLD_GREEN,
                icon,
                colors::RESET,
            );
        } else {
            println!("\n  {} Detected: JSON Web Token (JWT)\n", icon);
        }
        println!(
            "    Header:   {}",
            serde_json::to_string(&header_json).unwrap_or_default()
        );
        println!(
            "    Payload:  {}",
            serde_json::to_string_pretty(&payload_json).unwrap_or_default()
        );

        // Show expiry if present
        if let Some(exp) = payload_json.get("exp").and_then(|v| v.as_i64()) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let remaining = exp - now;
            if remaining < 0 {
                if use_color {
                    println!(
                        "    Expires:  {}EXPIRED {} ago{}",
                        colors::BOLD_RED,
                        format_duration(-remaining),
                        colors::RESET,
                    );
                } else {
                    println!("    Expires:  EXPIRED {} ago", format_duration(-remaining));
                }
            } else if use_color {
                println!(
                    "    Expires:  {}in {}{}",
                    colors::BOLD_GREEN,
                    format_duration(remaining),
                    colors::RESET,
                );
            } else {
                println!("    Expires:  in {}", format_duration(remaining));
            }
        }
        println!();
    }
    Ok(0)
}

fn base64url_decode(input: &str) -> Result<String> {
    // Convert base64url to standard base64
    let mut b64 = input.replace('-', "+").replace('_', "/");
    while !b64.len().is_multiple_of(4) {
        b64.push('=');
    }
    let bytes = crate::cert::parser::base64_decode_str(&b64)?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

fn format_duration(secs: i64) -> String {
    if secs < 60 {
        format!("{} seconds", secs)
    } else if secs < 3600 {
        format!("{} minutes", secs / 60)
    } else if secs < 86400 {
        format!("{} hours", secs / 3600)
    } else {
        format!("{} days", secs / 86400)
    }
}
