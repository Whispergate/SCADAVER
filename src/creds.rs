use serde::Deserialize;
use std::path::PathBuf;

/// Top-level structure of `~/.config/scadaver/creds.toml`.
#[derive(Deserialize, Default)]
pub struct CredConfig {
    #[serde(default)] pub siemens: SiemensCreds,
}

/// `S7Comm` only uses a password (no username).
#[derive(Deserialize, Default)]
pub struct SiemensCreds {
    pub passwords: Vec<String>,
}

pub fn creds_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("scadaver")
        .join("creds.toml")
}

/// Load the user credential file. Returns defaults if the file is missing or malformed.
pub fn load() -> CredConfig {
    std::fs::read_to_string(creds_path())
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

const SAMPLE_TOML: &str = r#"# SCADAver credential lists — loaded at runtime, no recompile needed.
# Operator entries are tried BEFORE the compiled-in defaults.
# Edit this file, then re-run "Try Default Passwords" — no restart required.

[siemens]
# S7Comm password-only (no username). Add known/leaked passwords first.
passwords = []
"#;

/// Write a commented sample `creds.toml` if none exists yet.
pub fn ensure_sample_exists() {
    let path = creds_path();
    if path.exists() {
        return;
    }
    if let Err(e) = std::fs::write(&path, SAMPLE_TOML) {
        eprintln!("[!] Could not write sample creds.toml to {}: {e}", path.display());
    }
}
