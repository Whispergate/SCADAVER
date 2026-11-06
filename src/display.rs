use clap::ValueEnum;
use colored::Colorize;
use std::sync::atomic::{AtomicU8, Ordering};

/// Controls how raw binary blocks are rendered by the non-interactive CLI.
///
/// `auto` is deliberately conservative: a buffer is shown as text only when
/// the complete buffer is valid, printable UTF-8.  PLC memory frequently
/// contains numbers and structures, so a partial ASCII preview must never be
/// presented as though it were a decoded string.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum ByteFormat {
    #[default]
    Auto,
    Text,
    Hex,
    Both,
}

static BYTE_FORMAT: AtomicU8 = AtomicU8::new(0);

pub fn set_byte_format(format: ByteFormat) {
    let value = match format {
        ByteFormat::Auto => 0,
        ByteFormat::Text => 1,
        ByteFormat::Hex => 2,
        ByteFormat::Both => 3,
    };
    BYTE_FORMAT.store(value, Ordering::Relaxed);
}

fn current_byte_format() -> ByteFormat {
    match BYTE_FORMAT.load(Ordering::Relaxed) {
        1 => ByteFormat::Text,
        2 => ByteFormat::Hex,
        3 => ByteFormat::Both,
        _ => ByteFormat::Auto,
    }
}

/// Configure terminal colour output once at process start.
///
/// `None` delegates to `colored`'s normal terminal/`NO_COLOR` detection,
/// while `Some` is used by the CLI's explicit `--color` switch.
pub fn set_color_override(force: Option<bool>) {
    if let Some(enabled) = force {
        colored::control::set_override(enabled);
    }
}

pub const BANNER: &str = r"
  ███████╗ ██████╗ █████╗ ██████╗  █████╗ ██╗   ██╗███████╗██████╗
  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔════╝██╔══██╗
  ███████╗██║     ███████║██║  ██║███████║██║   ██║█████╗  ██████╔╝
  ╚════██║██║     ██╔══██║██║  ██║██╔══██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
  ███████║╚██████╗██║  ██║██████╔╝██║  ██║ ╚████╔╝ ███████╗██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
";

pub fn print_banner() {
    println!("{}", BANNER.cyan().bold());
    println!(
        "{}",
        concat!("            Unified ICS Red Team Multi-Tool v", env!("CARGO_PKG_VERSION"), " (Rust)").cyan()
    );
    println!(
        "{}",
        "[*****************************************************************************]".cyan()
    );
    println!();
}

pub fn print_success(msg: &str) {
    println!("{} {}", "[+]".green().bold(), msg);
}

pub fn print_error(msg: &str) {
    println!("{} {}", "[-]".red().bold(), msg);
}

pub fn print_warn(msg: &str) {
    println!("{} {}", "[!]".yellow().bold(), msg);
}

pub fn print_info(msg: &str) {
    println!("{} {}", "[*]".cyan().bold(), msg);
}

/// Semantic styles shared by the non-interactive CLI renderers.
/// Keep the padding outside these helpers: ANSI escape sequences must not
/// participate in column-width calculations.
pub fn tag_name(value: &str) -> colored::ColoredString {
    value.cyan().bold()
}

pub fn address(value: &str) -> colored::ColoredString {
    value.cyan()
}

pub fn type_name(value: &str) -> colored::ColoredString {
    value.blue()
}

pub fn numeric(value: &str) -> colored::ColoredString {
    value.yellow()
}

pub fn text(value: &str) -> colored::ColoredString {
    value.green()
}

pub fn raw(value: &str) -> colored::ColoredString {
    value.dimmed()
}

pub fn boolean(value: &str) -> colored::ColoredString {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "true  (1)" | "on" => value.green().bold(),
        "false" | "false (0)" | "off" => value.red().bold(),
        _ => value.normal(),
    }
}

pub fn access(writable: bool) -> colored::ColoredString {
    if writable {
        "RW".green().bold()
    } else {
        "RO".dimmed()
    }
}

/// Render a decoded protocol value according to its representation.
pub fn decoded_value(value: &str) -> colored::ColoredString {
    let trimmed = value.trim();
    if matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "true" | "true  (1)" | "on" | "false" | "false (0)" | "off"
    ) {
        return boolean(value);
    }
    if trimmed.starts_with("0x") || trimmed.starts_with('[') || trimmed == "-" || trimmed == "?" {
        return raw(value);
    }
    if trimmed.starts_with('"') || trimmed.chars().any(char::is_alphabetic) {
        return text(value);
    }
    numeric(value)
}

/// A short printable preview for raw data blocks.  It intentionally does not
/// imply that arbitrary PLC memory is a string.
pub fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| {
            if byte.is_ascii_graphic() || byte == b' ' {
                char::from(byte)
            } else {
                '.'
            }
        })
        .collect()
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn printable_text(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    if text
        .chars()
        .all(|character| !character.is_control() && !character.is_whitespace() || character == ' ')
    {
        Some(format!("\"{text}\""))
    } else {
        None
    }
}

/// Render raw bytes without inventing a data type.  Use `--byte-format both`
/// when an operator needs both the exact bytes and the printable text view.
pub fn render_bytes_with_format(format: ByteFormat, bytes: &[u8]) -> String {
    let hex = hex_bytes(bytes);
    let text = printable_text(bytes);
    match format {
        ByteFormat::Hex => hex,
        ByteFormat::Both => text.map_or(hex.clone(), |text| format!("{hex}  {text}")),
        ByteFormat::Auto | ByteFormat::Text => text.unwrap_or(hex),
    }
}

pub fn render_bytes(bytes: &[u8]) -> String {
    render_bytes_with_format(current_byte_format(), bytes)
}

/// Render a command-fatal error without exposing request payloads or credentials.
/// The top error normally contains `SCADAver`'s operation context; `--verbose`
/// reveals the remaining safe anyhow cause chain for troubleshooting.
pub fn print_fatal_error(error: &anyhow::Error, verbose: bool) {
    let chain: Vec<String> = error
        .chain()
        .map(|cause| redact_error_text(&cause.to_string()))
        .collect();
    let summary = chain.first().map_or("Command failed", String::as_str);
    eprintln!("{} {}", "[-]".red().bold(), summary.red().bold());

    if let Some(cause) = chain.get(1) {
        eprintln!("    {} {}", "Cause:".yellow().bold(), cause);
    }
    if let Some(hint) = diagnostic_hint(&chain) {
        eprintln!("    {} {}", "Hint:".cyan().bold(), hint);
    }
    if verbose {
        if chain.len() > 1 {
            eprintln!("    {}", "Diagnostic chain:".cyan().bold());
            for (index, cause) in chain.iter().enumerate() {
                eprintln!("      {}. {cause}", index + 1);
            }
        }
    } else if chain.len() > 2 {
        eprintln!(
            "    {} rerun with {} for the full diagnostic chain.",
            "Tip:".cyan().bold(),
            "-v".cyan().bold()
        );
    }
}

fn diagnostic_hint(chain: &[String]) -> Option<&'static str> {
    let combined = chain.join(" ").to_ascii_lowercase();
    if combined.contains("[protocol default]") {
        return Some("The protocol default port was used. Pass -p <port> when the target uses a non-standard port.");
    }
    if combined.contains("connection refused") || combined.contains("actively refused") {
        return Some("The host rejected the TCP connection. Verify the service is running, the selected protocol, and its port.");
    }
    // The command context always includes `timeout=<n>s`; that setting is not
    // evidence of a timeout.  Only emit this hint for a transport failure.
    if combined.contains("timed out")
        || combined.contains("timeout error")
        || combined.contains("operation timeout")
    {
        return Some("The request timed out. Check reachability/firewall policy, then consider a larger --timeout value.");
    }
    if combined.contains("no device")
        || combined.contains("no responding")
        || combined.contains("no symbols")
    {
        return Some("Verify the protocol, target address, effective port, and any required credentials before retrying.");
    }
    None
}

fn redact_error_text(message: &str) -> String {
    let mut redacted = message.to_string();
    for marker in ["password=", "passwd=", "token=", "api_key=", "apikey="] {
        let mut start_at = 0;
        loop {
            let lower = redacted.to_ascii_lowercase();
            let Some(relative) = lower[start_at..].find(marker) else {
                break;
            };
            let start = start_at + relative + marker.len();
            let end = redacted[start..]
                .find(|ch: char| ch.is_whitespace() || matches!(ch, '&' | ',' | ';'))
                .map_or(redacted.len(), |offset| start + offset);
            redacted.replace_range(start..end, "[redacted]");
            start_at = start + "[redacted]".len();
            if start_at >= redacted.len() {
                break;
            }
        }
    }
    redacted
}

pub fn spinner_start(msg: &str) -> indicatif::ProgressBar {
    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_message(msg.to_string());
    pb
}

#[cfg(test)]
mod tests {
    use super::{
        ascii_preview, diagnostic_hint, redact_error_text, render_bytes_with_format, ByteFormat,
    };

    #[test]
    fn ascii_preview_keeps_printable_text_and_hides_binary() {
        assert_eq!(ascii_preview(b"PUMP\x00RUN"), "PUMP.RUN");
    }

    #[test]
    fn byte_renderer_uses_text_only_for_wholly_printable_buffers() {
        assert_eq!(
            render_bytes_with_format(ByteFormat::Auto, b"PUMP_RUN"),
            "\"PUMP_RUN\""
        );
        assert_eq!(
            render_bytes_with_format(ByteFormat::Auto, &[0xaa, 0x00]),
            "aa 00"
        );
        assert_eq!(
            render_bytes_with_format(ByteFormat::Both, b"OK"),
            "4f 4b  \"OK\""
        );
    }

    #[test]
    fn error_redaction_hides_common_secret_assignments() {
        let message = redact_error_text("password=hunter2 token=abc123 connection refused");
        assert!(!message.contains("hunter2"));
        assert!(!message.contains("abc123"));
        assert!(message.contains("connection refused"));
    }

    #[test]
    fn timeout_setting_does_not_create_a_false_timeout_hint() {
        let chain = [
            "set failed (protocol=Schneider, timeout=5s)".to_string(),
            "Schneider does not support 'set tag'".to_string(),
        ];
        assert_eq!(None, diagnostic_hint(&chain));
        assert!(diagnostic_hint(&["request timed out".to_string()]).is_some());
    }
}
