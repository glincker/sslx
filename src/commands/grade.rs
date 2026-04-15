use anyhow::Result;

use crate::cert::tls;
use crate::output::{box_chars, colors};

/// TLS grade scoring (A+ to F) — the screenshot moment
pub fn run(host: &str, port: u16, json: bool, no_color: bool) -> Result<i32> {
    let use_color = !no_color && !json && colors::should_color();

    let info = tls::connect(host, port, None, None, 10, true)?;

    let mut score = 100i32;
    let mut findings: Vec<Finding> = Vec::new();

    // 1. TLS Version scoring
    let tls_version = &info.tls_version;
    if tls_version.contains("1.3") {
        findings.push(Finding::pass("Protocol", "TLS 1.3"));
    } else if tls_version.contains("1.2") {
        findings.push(Finding::warn("Protocol", "TLS 1.2 (1.3 preferred)"));
        score -= 10;
    } else if tls_version.contains("1.1") {
        findings.push(Finding::fail("Protocol", "TLS 1.1 (deprecated)"));
        score -= 40;
    } else if tls_version.contains("1.0") {
        findings.push(Finding::fail("Protocol", "TLS 1.0 (deprecated, insecure)"));
        score -= 60;
    }

    // 2. Cipher suite scoring
    let cipher = &info.cipher_suite;
    if cipher.contains("AES") && (cipher.contains("GCM") || cipher.contains("CHACHA20")) {
        findings.push(Finding::pass("Cipher", &format!("{} (AEAD)", cipher)));
    } else if cipher.contains("AES") {
        findings.push(Finding::warn("Cipher", &format!("{} (CBC mode)", cipher)));
        score -= 10;
    } else if cipher.contains("RC4") || cipher.contains("DES") || cipher.contains("NULL") {
        findings.push(Finding::fail("Cipher", &format!("{} (insecure)", cipher)));
        score -= 50;
    } else {
        findings.push(Finding::pass("Cipher", cipher));
    }

    // 3. Certificate validity
    if let Some(leaf) = info.peer_certs.first() {
        let days = leaf.days_remaining();
        if leaf.is_expired() {
            findings.push(Finding::fail("Certificate", "EXPIRED"));
            score -= 100;
        } else if days <= 7 {
            findings.push(Finding::fail(
                "Certificate",
                &format!("Expiring in {} days", days),
            ));
            score -= 30;
        } else if days <= 30 {
            findings.push(Finding::warn(
                "Certificate",
                &format!("{} days remaining", days),
            ));
            score -= 10;
        } else {
            findings.push(Finding::pass(
                "Certificate",
                &format!("Valid, {} days remaining", days),
            ));
        }

        // 4. Key strength
        let key_bits = leaf.key_bits;
        let key_type = &leaf.key_type;
        match key_type {
            crate::cert::KeyType::Rsa => {
                if key_bits >= 2048 {
                    findings.push(Finding::pass("Key", &format!("RSA {} bit", key_bits)));
                } else {
                    findings.push(Finding::fail(
                        "Key",
                        &format!("RSA {} bit (weak, minimum 2048)", key_bits),
                    ));
                    score -= 40;
                }
            }
            crate::cert::KeyType::Ec(curve) => {
                findings.push(Finding::pass(
                    "Key",
                    &format!("ECDSA {} ({} bit)", curve, key_bits),
                ));
            }
            crate::cert::KeyType::Ed25519 => {
                findings.push(Finding::pass("Key", "Ed25519"));
            }
            _ => {
                findings.push(Finding::warn("Key", &format!("{}", key_type)));
            }
        }

        // 5. SANs check
        let host_in_sans = leaf
            .sans
            .iter()
            .any(|san| san == host || (san.starts_with("*.") && host.ends_with(&san[1..])));
        if host_in_sans {
            findings.push(Finding::pass("Hostname", &format!("{} in SANs", host)));
        } else {
            findings.push(Finding::fail("Hostname", &format!("{} NOT in SANs", host)));
            score -= 30;
        }

        // 6. Chain check
        let chain_len = info.peer_certs.len();
        if chain_len >= 2 {
            findings.push(Finding::pass(
                "Chain",
                &format!("Complete ({} certs)", chain_len),
            ));
        } else {
            findings.push(Finding::warn("Chain", "Single cert (may be incomplete)"));
            score -= 5;
        }
    } else {
        findings.push(Finding::fail("Certificate", "No certificate received"));
        score -= 100;
    }

    // 7. ALPN
    if info.alpn.as_deref() == Some("h2") {
        findings.push(Finding::pass("ALPN", "HTTP/2 supported"));
    } else if let Some(proto) = &info.alpn {
        findings.push(Finding::pass("ALPN", proto));
    } else {
        findings.push(Finding::warn("ALPN", "Not configured"));
        score -= 5;
    }

    let score = score.max(0);
    let grade = score_to_grade(score);

    if json {
        let output = serde_json::json!({
            "host": host,
            "port": port,
            "grade": grade,
            "score": score,
            "tls_version": info.tls_version,
            "cipher_suite": info.cipher_suite,
            "findings": findings.iter().map(|f| serde_json::json!({
                "category": f.category,
                "status": f.status,
                "detail": f.detail,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // The big grade display
        let grade_color = match grade.chars().next().unwrap_or('F') {
            'A' => colors::BOLD_GREEN,
            'B' => colors::GREEN,
            'C' | 'D' => colors::BOLD_YELLOW,
            _ => colors::BOLD_RED,
        };

        if use_color {
            println!();
            println!(
                "  {}╭──────────────────────────────────────────╮{}",
                colors::CYAN,
                colors::RESET
            );
            println!(
                "  {}│{}  {:<30}  Grade: {}{}{}  {}│{}",
                colors::CYAN,
                colors::RESET,
                format!("{}:{}", host, port),
                grade_color,
                grade,
                colors::RESET,
                colors::CYAN,
                colors::RESET,
            );
            println!(
                "  {}╰──────────────────────────────────────────╯{}",
                colors::CYAN,
                colors::RESET
            );
        } else {
            println!();
            println!("  ╭──────────────────────────────────────────╮");
            println!(
                "  │  {:<30}  Grade: {}  │",
                format!("{}:{}", host, port),
                grade
            );
            println!("  ╰──────────────────────────────────────────╯");
        }
        println!();

        for f in &findings {
            let icon = match f.status.as_str() {
                "pass" => {
                    if use_color {
                        format!(
                            "{}{}{}",
                            colors::BOLD_GREEN,
                            box_chars::CHECK,
                            colors::RESET
                        )
                    } else {
                        box_chars::CHECK.to_string()
                    }
                }
                "warn" => {
                    if use_color {
                        format!(
                            "{}{}{}",
                            colors::BOLD_YELLOW,
                            box_chars::WARNING,
                            colors::RESET
                        )
                    } else {
                        box_chars::WARNING.to_string()
                    }
                }
                _ => {
                    if use_color {
                        format!("{}{}{}", colors::BOLD_RED, box_chars::CROSS, colors::RESET)
                    } else {
                        box_chars::CROSS.to_string()
                    }
                }
            };
            println!("  {} {:<14}{}", icon, f.category, f.detail);
        }
        println!();
    }

    if score >= 80 {
        Ok(0)
    } else {
        Ok(1)
    }
}

struct Finding {
    category: String,
    status: String,
    detail: String,
}

impl Finding {
    fn pass(category: &str, detail: &str) -> Self {
        Self {
            category: category.to_string(),
            status: "pass".to_string(),
            detail: detail.to_string(),
        }
    }
    fn warn(category: &str, detail: &str) -> Self {
        Self {
            category: category.to_string(),
            status: "warn".to_string(),
            detail: detail.to_string(),
        }
    }
    fn fail(category: &str, detail: &str) -> Self {
        Self {
            category: category.to_string(),
            status: "fail".to_string(),
            detail: detail.to_string(),
        }
    }
}

fn score_to_grade(score: i32) -> &'static str {
    match score {
        95..=100 => "A+",
        90..=94 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
}
