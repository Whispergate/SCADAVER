mod cli;
mod creds;
mod db;
mod display;
mod tui;

pub use scadaver_rs::core;
pub use scadaver_rs::vendors;

fn main() {
    use clap::Parser;
    let args = cli::Args::parse();

    let launch_tui =
        args.command.is_none() || matches!(args.command, Some(cli::Verb::Tui));

    if launch_tui {
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
    } else if let Err(e) = cli::run(args) {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
