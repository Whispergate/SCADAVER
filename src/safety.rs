//! Safe mode for OT targets.
//!
//! A plant PLC is not a lab simulator. With `--safe-mode` the process takes a config that
//! inserts a delay before every scan, refuses verbs that write to, log in to, flash or
//! reset a device, and refuses hosts the operator has listed as fragile.
//!
//! The config is process-global because all three surfaces (cli, tui, web) reach the
//! protocol code through `ops`, and threading a parameter through every call site is
//! exactly how the previous drift started.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

use crate::protocol::Protocol;

/// Default spacing between probes. 250 ms is slow enough that a controller's comms task
/// is not hammered, fast enough that a /24 sweep is still usable.
pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(250);

/// Verb names that touch a device's state or credentials. Coarse on purpose: a safe gate
/// that misses a verb is worse than one that refuses a read-only verb with an odd name.
const MUTATING_MARKERS: &[&str] = &[
    "write", "set", "control", "exploit", "hijack", "fuzz", "flash", "reboot", "stop", "start",
    "upload", "download", "delete", "shell", "login", "creds", "auth", "reset", "restore",
    "install", "push",
];

#[derive(Debug, Clone)]
struct Config {
    interval: Duration,
    fragile: HashSet<String>,
}

static CONFIG: RwLock<Option<Config>> = RwLock::new(None);

/// Turn safe mode on. Replaces any previous config.
// One hasher: the config is process-global and no caller has a reason to pick another.
#[allow(clippy::implicit_hasher)]
pub fn enable(interval: Duration, fragile: HashSet<String>) {
    let mut slot = CONFIG
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = Some(Config { interval, fragile });
}

/// Turn safe mode off. Tests use this; nothing else should.
#[allow(dead_code)] // the bin crate compiles this module without a caller; the lib and its tests use it
pub fn disable() {
    let mut slot = CONFIG
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = None;
}

/// True when safe mode is on.
#[must_use]
pub fn enabled() -> bool {
    CONFIG
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
}

/// How many hosts are on the fragile list. For the startup banner.
#[must_use]
pub fn fragile_count() -> usize {
    CONFIG
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map_or(0, |c| c.fragile.len())
}

/// The gate every scan goes through. Err means the probe must not happen, and the text is
/// the reason, safe to show a user.
///
/// When safe mode is off this is a no-op. When on it sleeps `interval` and refuses
/// fragile hosts. The sleep is deliberate: OT safe mode IS slowness, and hiding it in a
/// background thread would let a caller queue more probes behind it.
pub fn pre_scan(protocol: Protocol, ip: &str) -> Result<(), String> {
    let cfg = CONFIG
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let Some(cfg) = cfg else {
        return Ok(());
    };
    if cfg.fragile.contains(ip) {
        return Err(format!(
            "safe mode: {ip} is on the fragile-hosts list, refusing to probe it with {protocol:?}"
        ));
    }
    std::thread::sleep(cfg.interval);
    Ok(())
}

/// True when a verb name looks like it changes device state or credentials.
#[must_use]
pub fn is_mutating_verb(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    MUTATING_MARKERS.iter().any(|m| lower.contains(m))
}

/// Err with a user-facing reason when safe mode is on and the verb is mutating.
pub fn refuse_if_mutating(name: &str) -> Result<(), String> {
    if enabled() && is_mutating_verb(name) {
        return Err(format!(
            "safe mode: refusing `{name}`, which changes device state or credentials. \
             Leave safe mode off for lab work against simulators."
        ));
    }
    Ok(())
}

/// Where the fragile-hosts list lives by default.
///
/// This mirrors `dirs::config_dir()`, which is what `config.rs` uses for `config.toml`:
/// `%APPDATA%` on Windows, `$XDG_CONFIG_HOME` or `~/.config` elsewhere. It used to build
/// `$HOME/.config/scadaver` by hand, so on Windows safe mode looked in a directory that does
/// not exist, loaded an empty fragile list, and still reported itself as on.
#[must_use]
pub fn default_fragile_path() -> PathBuf {
    config_base()
        .join("scadaver")
        .join("fragile_hosts.txt")
}

fn config_base() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return PathBuf::from(appdata);
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg);
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".config");
        }
    }
    PathBuf::from(".")
}

/// Read a fragile-hosts file: one address per line, `#` starts a comment, blank lines
/// ignored, missing file means empty. A malformed address is kept verbatim so the
/// operator sees it did not match, rather than being silently dropped.
#[must_use]
pub fn fragile_hosts_from_file(path: &Path) -> HashSet<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split('#').next().unwrap_or(line).trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The config is process-global, so tests that touch it must not run concurrently.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn off_by_default() {
        let _g = lock();
        disable();
        assert!(!enabled());
        assert!(pre_scan(Protocol::Modbus, "10.0.0.5").is_ok());
        assert!(refuse_if_mutating("WriteCoil").is_ok());
    }

    #[test]
    fn fragile_host_is_refused_with_a_reason() {
        let _g = lock();
        enable(Duration::ZERO, HashSet::from(["10.0.0.5".to_string()]));
        let err = pre_scan(Protocol::Siemens, "10.0.0.5").unwrap_err();
        assert!(err.contains("fragile"), "{err}");
        assert!(pre_scan(Protocol::Siemens, "10.0.0.6").is_ok());
        disable();
    }

    #[test]
    fn mutating_verbs_are_classified_coarsely() {
        let _g = lock();
        for v in [
            "WriteCoil",
            "SetRegister",
            "Control",
            "Exploit",
            "Creds",
            "FlashLed",
            "StopCpu",
        ] {
            assert!(is_mutating_verb(v), "{v} should be mutating");
        }
        for v in [
            "Scan", "Discover", "Info", "Identify", "Read", "List", "Status", "Export",
        ] {
            assert!(!is_mutating_verb(v), "{v} should be read-only");
        }
    }

    #[test]
    fn default_fragile_path_sits_beside_the_config() {
        // Same convention as `dirs::config_dir()`: <config base>/scadaver/fragile_hosts.txt.
        let fragile = default_fragile_path();
        assert_eq!(
            fragile.parent().and_then(|dir| dir.file_name()).and_then(|n| n.to_str()),
            Some("scadaver"),
            "{fragile:?}"
        );
        assert_eq!(
            fragile.file_name().and_then(|n| n.to_str()),
            Some("fragile_hosts.txt")
        );
        #[cfg(windows)]
        assert!(
            std::env::var_os("APPDATA").is_none_or(|appdata| fragile.starts_with(PathBuf::from(appdata))),
            "{fragile:?} should start under %APPDATA%"
        );
    }

    #[test]
    fn fragile_file_parsing() {
        let dir = std::env::temp_dir().join("scadaver-safety-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("fragile_hosts.txt");
        std::fs::write(&path, "# lab\n10.0.0.5\n\n10.0.0.6  # old S7-300\n").unwrap();
        let hosts = fragile_hosts_from_file(&path);
        assert!(hosts.contains("10.0.0.5"));
        assert!(hosts.contains("10.0.0.6"));
        assert_eq!(hosts.len(), 2);
        assert!(fragile_hosts_from_file(&dir.join("missing.txt")).is_empty());
    }
}
