pub mod json;
pub mod terminal;
pub mod util;

// ANSI escape codes for terminal colors
pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const GREEN: &str = "\x1b[32m";
    pub const CYAN: &str = "\x1b[36m";
    pub const BOLD_RED: &str = "\x1b[1;31m";
    pub const BOLD_GREEN: &str = "\x1b[1;32m";
    pub const BOLD_YELLOW: &str = "\x1b[1;33m";

    /// Check if color output should be used
    pub fn should_color() -> bool {
        // Respect NO_COLOR standard (https://no-color.org)
        if std::env::var("NO_COLOR").is_ok() {
            return false;
        }
        // Check if stdout is a terminal
        std::io::IsTerminal::is_terminal(&std::io::stdout())
    }
}

/// Unicode box-drawing characters for cert display
pub mod box_chars {
    pub const TOP_LEFT: &str = "╭";
    pub const TOP_RIGHT: &str = "╮";
    pub const BOTTOM_LEFT: &str = "╰";
    pub const BOTTOM_RIGHT: &str = "╯";
    pub const HORIZONTAL: &str = "─";
    pub const VERTICAL: &str = "│";
    pub const ARROW_DOWN: &str = "↓";
    pub const CHECK: &str = "✓";
    pub const CROSS: &str = "✗";
    pub const WARNING: &str = "!";
}

/// Render expiry status with color and progress bar
pub fn expiry_display(days_remaining: i64, use_color: bool) -> String {
    let (color, icon, label) = if days_remaining < 0 {
        (
            colors::BOLD_RED,
            box_chars::CROSS,
            format!("EXPIRED {} days ago", -days_remaining),
        )
    } else if days_remaining <= 7 {
        (
            colors::BOLD_RED,
            box_chars::WARNING,
            format!("EXPIRING in {} days", days_remaining),
        )
    } else if days_remaining <= 30 {
        (
            colors::BOLD_YELLOW,
            box_chars::WARNING,
            format!("in {} days", days_remaining),
        )
    } else {
        (
            colors::BOLD_GREEN,
            box_chars::CHECK,
            format!("{} days remaining", days_remaining),
        )
    };

    // Progress bar (10 chars wide)
    let total_days = 365.0_f64;
    let filled = ((days_remaining.max(0) as f64 / total_days) * 10.0).round() as usize;
    let filled = filled.min(10);
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(10 - filled));

    if use_color {
        format!("{}{}  {} [{}]{}", color, bar, label, icon, colors::RESET)
    } else {
        format!("{}  {} [{}]", bar, label, icon)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── expiry_display (no-color mode for deterministic output) ───────────────

    #[test]
    fn test_expiry_display_expired() {
        let out = expiry_display(-5, false);
        assert!(out.contains("EXPIRED"), "expected 'EXPIRED' in: {}", out);
        assert!(
            out.contains("5 days ago"),
            "expected '5 days ago' in: {}",
            out
        );
        assert!(
            out.contains(box_chars::CROSS),
            "expected CROSS icon in: {}",
            out
        );
    }

    #[test]
    fn test_expiry_display_zero_days() {
        let out = expiry_display(0, false);
        // 0 days is within the <=7 threshold — critical expiry
        assert!(out.contains("EXPIRING"), "expected 'EXPIRING' in: {}", out);
        assert!(out.contains("0 days"), "expected '0 days' in: {}", out);
    }

    #[test]
    fn test_expiry_display_seven_days() {
        let out = expiry_display(7, false);
        assert!(out.contains("EXPIRING"), "expected 'EXPIRING' in: {}", out);
        assert!(out.contains("7 days"), "expected '7 days' in: {}", out);
        assert!(
            out.contains(box_chars::WARNING),
            "expected WARNING icon in: {}",
            out
        );
    }

    #[test]
    fn test_expiry_display_thirty_days() {
        let out = expiry_display(30, false);
        assert!(
            out.contains("in 30 days"),
            "expected 'in 30 days' in: {}",
            out
        );
        assert!(
            out.contains(box_chars::WARNING),
            "expected WARNING icon in: {}",
            out
        );
    }

    #[test]
    fn test_expiry_display_healthy() {
        let out = expiry_display(365, false);
        assert!(
            out.contains("365 days remaining"),
            "expected '365 days remaining' in: {}",
            out
        );
        assert!(
            out.contains(box_chars::CHECK),
            "expected CHECK icon in: {}",
            out
        );
    }

    #[test]
    fn test_expiry_display_no_color_has_no_ansi_codes() {
        for days in [-10, 0, 7, 30, 365] {
            let out = expiry_display(days, false);
            assert!(
                !out.contains('\x1b'),
                "no-color output must not contain ANSI escape codes: {}",
                out
            );
        }
    }

    #[test]
    fn test_expiry_display_color_contains_ansi_codes() {
        for days in [-10, 0, 7, 30, 365] {
            let out = expiry_display(days, true);
            assert!(
                out.contains('\x1b'),
                "color output should contain ANSI escape codes: {}",
                out
            );
        }
    }

    #[test]
    fn test_expiry_display_progress_bar_length() {
        // The progress bar is always 10 characters wide (█ or ░)
        for days in [-10_i64, 0, 7, 30, 180, 365] {
            let out = expiry_display(days, false);
            let bar_chars = out.chars().filter(|&c| c == '█' || c == '░').count();
            assert_eq!(
                bar_chars, 10,
                "progress bar should be 10 chars for {} days",
                days
            );
        }
    }
}
