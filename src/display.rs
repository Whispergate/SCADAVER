use colored::Colorize;

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
        "            Unified ICS Red Team Multi-Tool v1.0 (Rust)".cyan()
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
