mod cli;
mod config;
mod creds;
mod import;
mod db;
mod display;
mod mqtt_shell;
mod tui;
mod web;

pub use scadaver::core;
pub use scadaver::vendors;

fn print_disclaimer() {
    eprintln!("SCADAVER \u{2014} authorized security research tool. For lab and CTF use only.");
    eprintln!("Unauthorized use against production systems is illegal.");
}

fn main() {
    use clap::Parser;
    print_disclaimer();
    let args = cli::Args::parse();
    let cfg = config::load();

    let launch_tui =
        args.command.is_none() || matches!(args.command, Some(cli::Verb::Tui));
    let launch_web = matches!(args.command, Some(cli::Verb::Web { .. }));

    if launch_tui {
        config::ensure_sample_exists();
        creds::ensure_sample_exists();
        let db_path = db::Database::default_path();
        let db = match db::Database::open(&db_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to open database at {}: {e:#}", db_path.display());
                std::process::exit(1);
            }
        };
        if let Err(e) = tui::run(&db) {
            eprintln!("Fatal: {e:#}");
            std::process::exit(1);
        }
    } else if launch_web {
        let Some(cli::Verb::Web { host, port }) = args.command else { unreachable!() };
        // Apply config defaults for web host/port if CLI values are the hardcoded defaults.
        let effective_host = cfg.web.host
            .filter(|h| host == "127.0.0.1" && !h.is_empty())
            .unwrap_or(host);
        let effective_port = cfg.web.port
            .filter(|_| port == 8888)
            .unwrap_or(port);
        let api_key = cfg.web.api_key.filter(|k| !k.is_empty());
        if let Err(e) = web::start(&effective_host, effective_port, api_key) {
            eprintln!("Web server error: {e:#}");
            std::process::exit(1);
        }
    } else if let Err(e) = cli::run(args, &cfg) {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
