use crate::cert::CertInfo;
use crate::output::{box_chars, colors, expiry_display};

/// Render a certificate in a beautiful box
pub fn render_cert(cert: &CertInfo, index: usize, total: usize, use_color: bool) -> String {
    let mut lines = Vec::new();
    let width: usize = 56;

    // Header
    let ca_label = if cert.is_ca { " (CA)" } else { "" };
    let header = format!(" Certificate {} of {}{} ", index + 1, total, ca_label);
    let padding = width.saturating_sub(header.len() + 2);
    let top = format!(
        "{}{}{}{}{}",
        box_chars::TOP_LEFT,
        box_chars::HORIZONTAL,
        header,
        box_chars::HORIZONTAL.repeat(padding),
        box_chars::TOP_RIGHT,
    );
    lines.push(if use_color {
        format!("{}{}{}", colors::CYAN, top, colors::RESET)
    } else {
        top
    });

    // Content rows
    let add_row = |lines: &mut Vec<String>, label: &str, value: &str, color: &str| {
        let content = format!("  {:<10}{}", label, value);
        let pad = width.saturating_sub(content.len());
        let row = format!(
            "{}{}{} {}",
            box_chars::VERTICAL,
            content,
            " ".repeat(pad),
            box_chars::VERTICAL,
        );
        if use_color && !color.is_empty() {
            let padding = " ".repeat(pad);
            lines.push(format!(
                "{}{}{}{} {}{}{}{}",
                colors::CYAN,
                box_chars::VERTICAL,
                color,
                content,
                colors::CYAN,
                padding,
                box_chars::VERTICAL,
                colors::RESET,
            ));
        } else {
            lines.push(row);
        }
    };

    add_row(&mut lines, "Subject:", &cert.subject, "");
    add_row(&mut lines, "Issuer:", &cert.issuer, colors::DIM);
    add_row(
        &mut lines,
        "Serial:",
        &truncate_hex(&cert.serial_hex, 24),
        colors::DIM,
    );

    // Empty line
    let empty = format!(
        "{}{} {}",
        box_chars::VERTICAL,
        " ".repeat(width),
        box_chars::VERTICAL,
    );
    lines.push(if use_color {
        format!("{}{}{}", colors::CYAN, &empty, colors::RESET)
    } else {
        empty.clone()
    });

    // Validity
    let valid_range = format!(
        "{} → {}",
        cert.not_before.format("%Y-%m-%d"),
        cert.not_after.format("%Y-%m-%d"),
    );
    add_row(&mut lines, "Valid:", &valid_range, "");

    // Expiry bar
    let expiry = expiry_display(cert.days_remaining(), use_color);
    let expiry_row = format!(
        "{}{}{}",
        if use_color { colors::CYAN } else { "" },
        box_chars::VERTICAL,
        if use_color { colors::RESET } else { "" },
    );
    lines.push(format!(
        "{}  {:<10}{}  {}",
        expiry_row, "Expires:", expiry, expiry_row
    ));

    // Empty line
    lines.push(if use_color {
        format!("{}{}{}", colors::CYAN, empty, colors::RESET)
    } else {
        empty.clone()
    });

    // Key info
    add_row(&mut lines, "Key:", &cert.key_description(), "");

    // SANs
    if !cert.sans.is_empty() {
        let sans_display = if cert.sans.len() <= 3 {
            cert.sans.join(", ")
        } else {
            format!(
                "{} + {} more",
                cert.sans[..2].join(", "),
                cert.sans.len() - 2
            )
        };
        add_row(&mut lines, "SANs:", &sans_display, "");
    }

    // Fingerprint
    add_row(
        &mut lines,
        "SHA-256:",
        &truncate_hex(&cert.sha256_fingerprint, 24),
        colors::DIM,
    );

    // Bottom border
    let bottom = format!(
        "{}{}{}",
        box_chars::BOTTOM_LEFT,
        box_chars::HORIZONTAL.repeat(width + 2),
        box_chars::BOTTOM_RIGHT,
    );
    lines.push(if use_color {
        format!("{}{}{}", colors::CYAN, bottom, colors::RESET)
    } else {
        bottom
    });

    lines.join("\n")
}

/// Render the "signed by" arrow between certs
pub fn render_chain_arrow(use_color: bool) -> String {
    let arrow = format!("  {} signed by", box_chars::ARROW_DOWN);
    if use_color {
        format!("{}{}{}", colors::DIM, arrow, colors::RESET)
    } else {
        arrow
    }
}

/// Render a verification result
pub fn render_verify_result(valid: bool, details: &str, use_color: bool) -> String {
    if valid {
        let icon = box_chars::CHECK;
        if use_color {
            format!(
                "  {}{} Certificate is valid{}\n{}",
                colors::BOLD_GREEN,
                icon,
                colors::RESET,
                details
            )
        } else {
            format!("  {} Certificate is valid\n{}", icon, details)
        }
    } else {
        let icon = box_chars::CROSS;
        if use_color {
            format!(
                "  {}{} Certificate verification failed{}\n{}",
                colors::BOLD_RED,
                icon,
                colors::RESET,
                details
            )
        } else {
            format!("  {} Certificate verification failed\n{}", icon, details)
        }
    }
}

/// Render TLS connection header
pub fn render_connection_header(
    host: &str,
    port: u16,
    tls_version: &str,
    cipher: &str,
    alpn: Option<&str>,
    use_color: bool,
) -> String {
    let mut out = String::new();

    let header = format!("Connection to {}:{}", host, port);
    if use_color {
        out.push_str(&format!("{}{}{}\n\n", colors::BOLD, header, colors::RESET));
    } else {
        out.push_str(&format!("{}\n\n", header));
    }

    let tls_info = format!("  {} · {}", tls_version, cipher);
    if use_color {
        out.push_str(&format!("{}{}{}\n", colors::GREEN, tls_info, colors::RESET));
    } else {
        out.push_str(&format!("{}\n", tls_info));
    }

    if let Some(alpn_proto) = alpn {
        out.push_str(&format!("  ALPN: {}\n", alpn_proto));
    }

    out.push_str("\n  Chain:");
    out
}

fn truncate_hex(hex: &str, max_len: usize) -> String {
    if hex.len() <= max_len {
        hex.to_string()
    } else {
        format!("{}...", &hex[..max_len])
    }
}
