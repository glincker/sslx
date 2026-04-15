use anyhow::Result;

use crate::cert::tls;
use crate::output::util::parse_host_port;
use crate::output::{box_chars, colors};

pub fn run(hosts: &[String], json: bool, no_color: bool) -> Result<i32> {
    let use_color = !no_color && !json && colors::should_color();

    let mut results: Vec<HostExpiry> = Vec::new();
    let mut any_critical = false;

    for host_input in hosts {
        let (host, port) = parse_host_port(host_input);

        match tls::connect(&host, port, None, None, 10, true) {
            Ok(info) => {
                if let Some(leaf) = info.peer_certs.first() {
                    let days = leaf.days_remaining();
                    let status = if leaf.is_expired() {
                        any_critical = true;
                        ExpiryStatus::Expired
                    } else if days <= 7 {
                        any_critical = true;
                        ExpiryStatus::Critical
                    } else if days <= 30 {
                        ExpiryStatus::Warning
                    } else {
                        ExpiryStatus::Ok
                    };
                    results.push(HostExpiry {
                        host: format!("{}:{}", host, port),
                        subject: leaf.subject.clone(),
                        expires: leaf.not_after.format("%Y-%m-%d"),
                        days,
                        status,
                        error: None,
                    });
                }
            }
            Err(e) => {
                any_critical = true;
                results.push(HostExpiry {
                    host: format!("{}:{}", host, port),
                    subject: String::new(),
                    expires: String::new(),
                    days: -1,
                    status: ExpiryStatus::Error,
                    error: Some(format!("{}", e)),
                });
            }
        }
    }

    if json {
        let output: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "host": r.host,
                    "subject": r.subject,
                    "expires": r.expires,
                    "days_remaining": r.days,
                    "status": format!("{:?}", r.status),
                    "error": r.error,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!();

        // Header
        if use_color {
            println!(
                "  {}{}  {:<30} {:<14} {:>6}  Status{}",
                colors::BOLD,
                colors::DIM,
                "Host",
                "Expires",
                "Days",
                colors::RESET,
            );
        } else {
            println!("  {:<30} {:<14} {:>6}  Status", "Host", "Expires", "Days");
        }

        let separator = format!("  {}", "─".repeat(68));
        if use_color {
            println!("{}{}{}", colors::DIM, separator, colors::RESET);
        } else {
            println!("{}", separator);
        }

        for r in &results {
            let (icon, status_color, status_text) = match r.status {
                ExpiryStatus::Ok => (box_chars::CHECK, colors::BOLD_GREEN, "OK"),
                ExpiryStatus::Warning => (box_chars::WARNING, colors::BOLD_YELLOW, "WARNING"),
                ExpiryStatus::Critical => (box_chars::CROSS, colors::BOLD_RED, "CRITICAL"),
                ExpiryStatus::Expired => (box_chars::CROSS, colors::BOLD_RED, "EXPIRED"),
                ExpiryStatus::Error => (box_chars::CROSS, colors::BOLD_RED, "ERROR"),
            };

            if use_color {
                println!(
                    "  {}{}{} {:<30} {:<14} {:>6}  {}{}{}",
                    status_color,
                    icon,
                    colors::RESET,
                    r.host,
                    r.expires,
                    if r.days >= 0 {
                        r.days.to_string()
                    } else {
                        "-".to_string()
                    },
                    status_color,
                    status_text,
                    colors::RESET,
                );
            } else {
                println!(
                    "  {} {:<30} {:<14} {:>6}  {}",
                    icon,
                    r.host,
                    r.expires,
                    if r.days >= 0 {
                        r.days.to_string()
                    } else {
                        "-".to_string()
                    },
                    status_text,
                );
            }

            if let Some(err) = &r.error {
                if use_color {
                    println!("    {}{}{}", colors::DIM, err, colors::RESET);
                } else {
                    println!("    {}", err);
                }
            }
        }
        println!();
    }

    if any_critical {
        Ok(1)
    } else {
        Ok(0)
    }
}

struct HostExpiry {
    host: String,
    subject: String,
    expires: String,
    days: i64,
    status: ExpiryStatus,
    error: Option<String>,
}

#[derive(Debug)]
enum ExpiryStatus {
    Ok,
    Warning,
    Critical,
    Expired,
    Error,
}
