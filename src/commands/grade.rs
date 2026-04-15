use anyhow::Result;

use crate::cert::tls;
use crate::output::{box_chars, colors};

pub fn run(host: &str, port: u16, json: bool, no_color: bool) -> Result<i32> {
    let use_color = !no_color && !json && colors::should_color();

    let info = tls::connect(host, port, None, None, 10, true)?;

    let mut score = 100i32;
    let mut findings: Vec<Finding> = Vec::new();

    // 1. TLS Version scoring
    let tls_version = &info.tls_version;
    if tls_version.contains("1.3") {
        findings.push(Finding {
            category: "Protocol",
            severity: Severity::Pass,
            detail: "TLS 1.3".into(),
        });
    } else if tls_version.contains("1.2") {
        findings.push(Finding {
            category: "Protocol",
            severity: Severity::Warn,
            detail: "TLS 1.2 (1.3 preferred)".into(),
        });
        score -= 10;
    } else if tls_version.contains("1.1") {
        findings.push(Finding {
            category: "Protocol",
            severity: Severity::Fail,
            detail: "TLS 1.1 (deprecated)".into(),
        });
        score -= 40;
    } else if tls_version.contains("1.0") {
        findings.push(Finding {
            category: "Protocol",
            severity: Severity::Fail,
            detail: "TLS 1.0 (deprecated, insecure)".into(),
        });
        score -= 60;
    }

    // 2. Cipher suite scoring
    let cipher = &info.cipher_suite;
    if cipher.contains("AES") && (cipher.contains("GCM") || cipher.contains("CHACHA20")) {
        findings.push(Finding {
            category: "Cipher",
            severity: Severity::Pass,
            detail: format!("{} (AEAD)", cipher),
        });
    } else if cipher.contains("AES") {
        findings.push(Finding {
            category: "Cipher",
            severity: Severity::Warn,
            detail: format!("{} (CBC mode)", cipher),
        });
        score -= 10;
    } else if cipher.contains("RC4") || cipher.contains("DES") || cipher.contains("NULL") {
        findings.push(Finding {
            category: "Cipher",
            severity: Severity::Fail,
            detail: format!("{} (insecure)", cipher),
        });
        score -= 50;
    } else {
        findings.push(Finding {
            category: "Cipher",
            severity: Severity::Pass,
            detail: cipher.clone(),
        });
    }

    // 3. Certificate validity
    if let Some(leaf) = info.peer_certs.first() {
        let days = leaf.days_remaining();
        if leaf.is_expired() {
            findings.push(Finding {
                category: "Certificate",
                severity: Severity::Fail,
                detail: "EXPIRED".into(),
            });
            score -= 100;
        } else if days <= 7 {
            findings.push(Finding {
                category: "Certificate",
                severity: Severity::Fail,
                detail: format!("Expiring in {} days", days),
            });
            score -= 30;
        } else if days <= 30 {
            findings.push(Finding {
                category: "Certificate",
                severity: Severity::Warn,
                detail: format!("{} days remaining", days),
            });
            score -= 10;
        } else {
            findings.push(Finding {
                category: "Certificate",
                severity: Severity::Pass,
                detail: format!("Valid, {} days remaining", days),
            });
        }

        // 4. Key strength
        let key_bits = leaf.key_bits;
        let key_type = &leaf.key_type;
        match key_type {
            crate::cert::KeyType::Rsa => {
                if key_bits >= 2048 {
                    findings.push(Finding {
                        category: "Key",
                        severity: Severity::Pass,
                        detail: format!("RSA {} bit", key_bits),
                    });
                } else {
                    findings.push(Finding {
                        category: "Key",
                        severity: Severity::Fail,
                        detail: format!("RSA {} bit (weak, minimum 2048)", key_bits),
                    });
                    score -= 40;
                }
            }
            crate::cert::KeyType::Ec(curve) => {
                findings.push(Finding {
                    category: "Key",
                    severity: Severity::Pass,
                    detail: format!("ECDSA {} ({} bit)", curve, key_bits),
                });
            }
            crate::cert::KeyType::Ed25519 => {
                findings.push(Finding {
                    category: "Key",
                    severity: Severity::Pass,
                    detail: "Ed25519".into(),
                });
            }
            _ => {
                findings.push(Finding {
                    category: "Key",
                    severity: Severity::Warn,
                    detail: format!("{}", key_type),
                });
            }
        }

        // 5. SANs check
        let host_in_sans = leaf
            .sans
            .iter()
            .any(|san| san == host || (san.starts_with("*.") && host.ends_with(&san[1..])));
        if host_in_sans {
            findings.push(Finding {
                category: "Hostname",
                severity: Severity::Pass,
                detail: format!("{} in SANs", host),
            });
        } else {
            findings.push(Finding {
                category: "Hostname",
                severity: Severity::Fail,
                detail: format!("{} NOT in SANs", host),
            });
            score -= 30;
        }

        // 6. Chain check
        let chain_len = info.peer_certs.len();
        if chain_len >= 2 {
            findings.push(Finding {
                category: "Chain",
                severity: Severity::Pass,
                detail: format!("Complete ({} certs)", chain_len),
            });
        } else {
            findings.push(Finding {
                category: "Chain",
                severity: Severity::Warn,
                detail: "Single cert (may be incomplete)".into(),
            });
            score -= 5;
        }
    } else {
        findings.push(Finding {
            category: "Certificate",
            severity: Severity::Fail,
            detail: "No certificate received".into(),
        });
        score -= 100;
    }

    // 7. ALPN
    if info.alpn.as_deref() == Some("h2") {
        findings.push(Finding {
            category: "ALPN",
            severity: Severity::Pass,
            detail: "HTTP/2 supported".into(),
        });
    } else if let Some(proto) = &info.alpn {
        findings.push(Finding {
            category: "ALPN",
            severity: Severity::Pass,
            detail: proto.clone(),
        });
    } else {
        findings.push(Finding {
            category: "ALPN",
            severity: Severity::Warn,
            detail: "Not configured".into(),
        });
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
                "status": match f.severity { Severity::Pass => "pass", Severity::Warn => "warn", Severity::Fail => "fail" },
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
            let icon = match f.severity {
                Severity::Pass => {
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
                Severity::Warn => {
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
                Severity::Fail => {
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

enum Severity {
    Pass,
    Warn,
    Fail,
}

struct Finding {
    category: &'static str,
    severity: Severity,
    detail: String,
}

pub(crate) fn score_to_grade(score: i32) -> &'static str {
    match score {
        95..=100 => "A+",
        90..=94 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── score_to_grade boundary values ────────────────────────────────────────

    #[test]
    fn test_grade_a_plus_boundaries() {
        assert_eq!(score_to_grade(100), "A+");
        assert_eq!(score_to_grade(95), "A+");
    }

    #[test]
    fn test_grade_a_boundaries() {
        assert_eq!(score_to_grade(94), "A");
        assert_eq!(score_to_grade(90), "A");
    }

    #[test]
    fn test_grade_b_boundaries() {
        assert_eq!(score_to_grade(89), "B");
        assert_eq!(score_to_grade(80), "B");
    }

    #[test]
    fn test_grade_c_boundaries() {
        assert_eq!(score_to_grade(79), "C");
        assert_eq!(score_to_grade(70), "C");
    }

    #[test]
    fn test_grade_d_boundaries() {
        assert_eq!(score_to_grade(69), "D");
        assert_eq!(score_to_grade(60), "D");
    }

    #[test]
    fn test_grade_f_boundaries() {
        assert_eq!(score_to_grade(59), "F");
        assert_eq!(score_to_grade(0), "F");
    }

    #[test]
    fn test_grade_f_negative_score() {
        // score is clamped to 0 in run(), but the function itself should handle negatives
        assert_eq!(score_to_grade(-1), "F");
        assert_eq!(score_to_grade(-100), "F");
    }

    #[test]
    fn test_grade_midpoints() {
        assert_eq!(score_to_grade(97), "A+");
        assert_eq!(score_to_grade(92), "A");
        assert_eq!(score_to_grade(85), "B");
        assert_eq!(score_to_grade(75), "C");
        assert_eq!(score_to_grade(65), "D");
        assert_eq!(score_to_grade(30), "F");
    }
}
