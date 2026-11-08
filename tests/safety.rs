//! Safe mode is a safety property, not a feature: these tests pin the three guarantees
//! (inter-probe delay, mutating-verb refusal, fragile-host refusal) at the library
//! boundary a consumer actually sees.
//!
//! `safety` keeps its config in a process-global `RwLock`, so every test that reads or
//! writes it takes `TEST_LOCK`. Integration tests in one binary run on parallel threads,
//! and an unlocked test would silently observe another test's config.

use scadaver::protocol::Protocol;
use scadaver::safety;
use std::collections::HashSet;
#[cfg(not(windows))]
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Serializes every test that touches the global config.
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn fragile(hosts: &[&str]) -> HashSet<String> {
    hosts.iter().map(|host| (*host).to_string()).collect()
}

#[test]
fn safe_mode_is_off_until_enabled() {
    let _guard = lock();
    safety::disable();

    assert!(!safety::enabled(), "safe mode must not be on by default");
    assert_eq!(safety::fragile_count(), 0);

    // Off means every gate is a no-op, including the mutating-verb gate.
    assert!(safety::pre_scan(Protocol::Modbus, "10.0.0.5").is_ok());
    assert!(safety::refuse_if_mutating("WriteCoil").is_ok());
}

#[test]
fn enable_and_disable_round_trip() {
    let _guard = lock();
    safety::disable();
    assert!(!safety::enabled());

    safety::enable(Duration::ZERO, fragile(&["10.0.0.5", "10.0.0.6"]));
    assert!(safety::enabled());
    assert_eq!(safety::fragile_count(), 2);

    // Enabling again replaces the config instead of merging into it.
    safety::enable(Duration::ZERO, fragile(&["10.0.0.9"]));
    assert!(safety::enabled());
    assert_eq!(safety::fragile_count(), 1);
    assert!(
        safety::pre_scan(Protocol::Modbus, "10.0.0.5").is_ok(),
        "a host from the previous config must not stay fragile"
    );

    safety::disable();
    assert!(!safety::enabled());
    assert_eq!(safety::fragile_count(), 0);
}

#[test]
fn fragile_host_is_refused_with_a_reason() {
    let _guard = lock();
    safety::enable(Duration::ZERO, fragile(&["10.0.0.5"]));

    let reason = safety::pre_scan(Protocol::Siemens, "10.0.0.5").unwrap_err();
    assert!(
        reason.contains("fragile"),
        "reason must name the list: {reason}"
    );
    assert!(
        reason.contains("10.0.0.5"),
        "reason must name the host: {reason}"
    );
    assert!(
        reason.contains("Siemens"),
        "reason must name the protocol: {reason}"
    );

    // A host that is not listed is still probed.
    assert!(safety::pre_scan(Protocol::Siemens, "10.0.0.6").is_ok());
    // Matching is exact: a neighbour is not fragile by association.
    assert!(safety::pre_scan(Protocol::Siemens, "10.0.0.50").is_ok());

    safety::disable();
}

#[test]
fn mutating_verbs_are_refused_only_when_enabled() {
    let _guard = lock();
    safety::disable();
    assert!(
        safety::refuse_if_mutating("WriteCoil").is_ok(),
        "with safe mode off nothing is refused"
    );

    safety::enable(Duration::ZERO, HashSet::new());
    let reason = safety::refuse_if_mutating("SetRegister").unwrap_err();
    assert!(
        reason.contains("safe mode"),
        "reason must say why: {reason}"
    );
    assert!(
        reason.contains("SetRegister"),
        "reason must name the verb: {reason}"
    );

    // Read-only verbs stay usable inside safe mode.
    assert!(safety::refuse_if_mutating("Scan").is_ok());
    assert!(safety::refuse_if_mutating("GetInfo").is_ok());

    safety::disable();
    assert!(
        safety::refuse_if_mutating("SetRegister").is_ok(),
        "disabling must lift the refusal"
    );
}

#[test]
fn mutating_verb_table() {
    let mutating = [
        "WriteCoil",
        "WriteRegister",
        "SetRegister",
        "Control",
        "Exploit",
        "Hijack",
        "Fuzz",
        "FlashFirmware",
        "Reboot",
        "StopCpu",
        "StartCpu",
        "UploadProgram",
        "DownloadProgram",
        "DeleteFile",
        "Shell",
        "Login",
        "Creds",
        "Auth",
        "Reset",
        "Restore",
        "Install",
        "Push",
    ];
    let read_only = [
        "Scan",
        "Discover",
        "Autodetect",
        "GetInfo",
        "Info",
        "Identify",
        "ReadHoldingRegisters",
        "ReadCoils",
        "ListDevices",
        "Status",
        "Ping",
        "Snapshot",
        "Diagnostics",
        "Export",
    ];

    for verb in mutating {
        assert!(
            safety::is_mutating_verb(verb),
            "{verb} must be classified as mutating"
        );
    }
    for verb in read_only {
        assert!(
            !safety::is_mutating_verb(verb),
            "{verb} must be classified as read-only"
        );
    }

    // Matching is case-insensitive because the gate sees Debug-formatted verb names.
    assert!(safety::is_mutating_verb("wRiTeCoIl"));
    assert_eq!(
        safety::is_mutating_verb("WriteCoil"),
        safety::is_mutating_verb("writecoil")
    );
}

#[test]
fn fragile_hosts_file_parsing() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("fragile_hosts.txt");
    let fixture = concat!(
        "# hosts the plant cannot survive a probe against\n",
        "\n",
        "10.0.0.5\n",
        "  10.0.0.6\t\n",
        "10.0.0.7  # old S7-300, comms task drops under load\n",
        "#10.0.0.8\n",
        "not-an-ip  # typo kept verbatim\n",
    );
    std::fs::write(&path, fixture).expect("write fixture");

    let hosts = safety::fragile_hosts_from_file(&path);
    assert!(hosts.contains("10.0.0.5"), "plain lines must load");
    assert!(
        hosts.contains("10.0.0.6"),
        "surrounding whitespace must be trimmed"
    );
    assert!(
        hosts.contains("10.0.0.7"),
        "a trailing comment must not join the address"
    );
    assert!(!hosts.contains("10.0.0.7  # old S7-300, comms task drops under load"));
    assert!(
        !hosts.contains("10.0.0.8"),
        "a commented-out address must not load"
    );
    assert!(
        hosts.contains("not-an-ip"),
        "a malformed line is kept so the operator can see it did not match"
    );
    assert_eq!(hosts.len(), 4, "unexpected entries: {hosts:?}");

    // Comment-only file: valid, means "nothing fragile".
    let empty_path = dir.path().join("comments_only.txt");
    std::fs::write(&empty_path, "# nothing here yet\n\n# still nothing\n").expect("write fixture");
    assert!(
        safety::fragile_hosts_from_file(&empty_path).is_empty(),
        "expected empty, got {:?}",
        safety::fragile_hosts_from_file(&empty_path)
    );

    // Missing file is not an error; it means an empty list.
    let missing = dir.path().join("does_not_exist.txt");
    assert!(
        safety::fragile_hosts_from_file(&missing).is_empty(),
        "expected empty, got {:?}",
        safety::fragile_hosts_from_file(&missing)
    );

    // The parsed set is what the gate honours once handed to `enable`.
    safety::enable(Duration::ZERO, hosts);
    assert_eq!(safety::fragile_count(), 4);
    assert!(safety::pre_scan(Protocol::Modbus, "10.0.0.7").is_err());
    assert!(safety::pre_scan(Protocol::Modbus, "10.0.0.9").is_ok());
    safety::disable();
}

#[test]
fn interval_is_applied_before_each_probe() {
    let _guard = lock();
    let interval = Duration::from_millis(50);

    safety::enable(interval, HashSet::new());
    let start = Instant::now();
    safety::pre_scan(Protocol::Modbus, "10.0.0.7").expect("host is not fragile");
    let gated = start.elapsed();
    // `sleep` promises "at least", so assert a floor below the nominal interval, not equality.
    assert!(
        gated >= Duration::from_millis(40),
        "safe mode must delay the probe, took {gated:?}"
    );

    // A fragile host is refused, not delayed: the refusal must not burn a probe slot.
    safety::enable(interval, fragile(&["10.0.0.8"]));
    let start = Instant::now();
    assert!(safety::pre_scan(Protocol::Modbus, "10.0.0.8").is_err());
    let refused = start.elapsed();
    assert!(
        refused < Duration::from_millis(40),
        "refusal must be immediate, took {refused:?}"
    );

    // Off is a no-op, not a zero-length sleep.
    safety::disable();
    let start = Instant::now();
    safety::pre_scan(Protocol::Modbus, "10.0.0.7").expect("safe mode is off");
    let bare = start.elapsed();
    assert!(
        bare < Duration::from_millis(40),
        "with safe mode off pre_scan must return immediately, took {bare:?}"
    );
}

#[test]
fn default_fragile_path_sits_beside_the_config() {
    // The path must follow `dirs::config_dir()`, which is what `config.rs` uses for
    // config.toml: %APPDATA%\scadaver on Windows, $XDG_CONFIG_HOME or ~/.config elsewhere.
    let path = safety::default_fragile_path();
    assert_eq!(
        path.parent()
            .and_then(|dir| dir.file_name())
            .and_then(|n| n.to_str()),
        Some("scadaver"),
        "{}",
        path.display()
    );
    assert_eq!(
        path.file_name().and_then(|n| n.to_str()),
        Some("fragile_hosts.txt"),
        "{}",
        path.display()
    );
    #[cfg(windows)]
    {
        let appdata = std::env::var_os("APPDATA").expect("APPDATA is set on Windows");
        assert!(
            path.starts_with(std::path::PathBuf::from(appdata)),
            "{} should sit under %APPDATA%",
            path.display()
        );
    }
    #[cfg(not(windows))]
    assert!(
        path.ends_with(
            Path::new(".config")
                .join("scadaver")
                .join("fragile_hosts.txt")
        ),
        "{}",
        path.display()
    );
}
