use serde::Deserialize;
use std::path::PathBuf;

/// Top-level structure of `~/.config/scadaver/creds.toml`.
#[derive(Deserialize, Default)]
pub struct CredConfig {
    #[serde(default)] pub siemens: SiemensCreds,
    #[serde(default)] pub http: HttpCreds,
}

/// `S7Comm` only uses a password (no username).
#[derive(Deserialize, Default)]
pub struct SiemensCreds {
    pub passwords: Vec<String>,
}

/// HTTP Basic Auth credential pairs. Entries are tried before the built-in defaults.
#[derive(Deserialize, Default)]
pub struct HttpCreds {
    /// Each inner array is `[username, password]`.
    pub credentials: Vec<[String; 2]>,
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

/// Load a wordlist from a plain-text file (`user:pass` per line).
/// Lines starting with `#` and blank lines are skipped.
/// The colon split is on the *first* colon, so passwords may contain colons.
pub fn load_wordlist(path: &str) -> anyhow::Result<Vec<(String, String)>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read wordlist {path}: {e}"))?;
    let pairs = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once(':').map(|(u, p)| (u.to_string(), p.to_string())))
        .collect();
    Ok(pairs)
}

const SAMPLE_TOML: &str = r"# SCADAver credential lists: loaded at runtime, no recompile needed.
# Operator entries are tried BEFORE the compiled-in defaults.
# Edit this file, then re-run the relevant exploit: no restart required.

[siemens]
# S7Comm password-only (no username). Add known/leaked passwords first.
passwords = []

[http]
# HTTP Basic Auth pairs tried before the built-in ICS defaults.
# Format: each entry is [username, password].
credentials = []
";

/// Write a commented sample `creds.toml` if none exists yet.
pub fn ensure_sample_exists() {
    let path = creds_path();
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, SAMPLE_TOML) {
        eprintln!("[!] Could not write sample creds.toml to {}: {e}", path.display());
    }
}
