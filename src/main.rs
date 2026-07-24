mod cli;
mod core;
mod db;
mod display;
mod interactive;
mod tui;
mod vendors;

fn main() {
    use clap::Parser;
    let args = cli::Args::parse();
    if args.command.is_none() {
        let db_path = db::Database::default_path();
        let db = match db::Database::open(&db_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to open database at {db_path:?}: {e:#}");
                std::process::exit(1);
            }
        };
        if let Err(e) = tui::run(db) {
            eprintln!("Fatal: {e:#}");
            std::process::exit(1);
        }
    } else if let Err(e) = cli::run(args) {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
