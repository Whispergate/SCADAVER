use serde::Deserialize;
use std::path::PathBuf;

/// Top-level structure of `~/.config/scadaver/config.toml`.
#[derive(Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)] pub defaults: DefaultsConfig,
    #[serde(default)] pub web: WebConfig,
    // Consumed by MQTT TLS feature (session.rs integration pending).
    #[allow(dead_code)]
    #[serde(default)] pub mqtt: MqttConfig,
}

#[derive(Deserialize, Default)]
pub struct DefaultsConfig {
    /// Timeout in seconds for all network operations (default: 5)
    pub timeout: Option<u64>,
    /// Enable stealth mode by default (randomise probe order, add jitter)
    pub stealth: Option<bool>,
}

#[derive(Deserialize, Default)]
pub struct WebConfig {
    /// Host to bind the web interface to (default: 127.0.0.1)
    pub host: Option<String>,
    /// Port for the web interface (default: 8888)
    pub port: Option<u16>,
    /// API key for the web interface (default: auto-generated per session)
    pub api_key: Option<String>,
}

// Fields consumed by the MQTT TLS feature (session.rs integration pending).
#[allow(dead_code)]
#[derive(Deserialize, Default)]
pub struct MqttConfig {
    /// Default MQTT broker port (default: 1883)
    pub port: Option<u16>,
    /// Enable TLS for MQTT connections by default
    pub tls: Option<bool>,
}

pub fn config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("scadaver")
        .join("config.toml")
}

/// Load the config file. Returns defaults if the file is missing or malformed.
pub fn load() -> ConfigFile {
    std::fs::read_to_string(config_path())
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

const SAMPLE_CONFIG: &str = r"# SCADAver configuration file.
# Uncomment and edit values to override the built-in defaults.
# CLI flags always take precedence over settings in this file.

[defaults]
# timeout = 5        # Network operation timeout in seconds
# stealth = false    # Randomise probe order and add inter-probe jitter

[web]
# host = '127.0.0.1' # Bind address for the web interface
# port = 8888         # Port for the web interface
# api_key = ''        # Fixed API key (leave empty for auto-generated per-session)

[mqtt]
# port = 1883         # Default MQTT broker port
# tls = false         # Enable TLS by default for MQTT connections
";

/// Write a commented sample `config.toml` if none exists yet.
pub fn ensure_sample_exists() {
    let path = config_path();
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, SAMPLE_CONFIG) {
        eprintln!("[!] Could not write sample config.toml to {}: {e}", path.display());
    }
}
