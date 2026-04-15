pub mod json;
pub mod terminal;

/// Colors via ANSI escape codes — no dependency needed
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
