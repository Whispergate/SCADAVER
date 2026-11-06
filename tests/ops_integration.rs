// ops_integration.rs — end-to-end tests via the shared ops::scan_ip dispatch layer.
//
// These tests exercise the same code path used by CLI, TUI, and Web simultaneously,
// because all three surfaces delegate to crate::ops::scan_ip.
//
// Requires Python simulators in sim/ and scripts/.
// Run with:
//   cargo test --test ops_integration -- --ignored --nocapture --test-threads=1
//
// Never run without --test-threads=1: each test binds a port; parallel runs collide.

use scadaver::protocol::Protocol;
use std::time::Duration;

// ── SimulatorGuard ────────────────────────────────────────────────────────────

struct SimulatorGuard(std::process::Child);

impl SimulatorGuard {
    fn spawn(program: &str, args: &[&str]) -> Self {
        let child = std::process::Command::new(program)
            .args(args)
            .current_dir(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            )
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to start simulator '{program}': {e}"));
        Self(child)
    }
}

impl Drop for SimulatorGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn collect_out(lines: &std::sync::Mutex<Vec<String>>) -> String {
    lines.lock().unwrap().join("\n")
}

// ── Modbus ────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/modbus_sim.py on port 21502"]
fn ops_modbus_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/modbus_sim.py", "--host", "127.0.0.1", "--port", "21502"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Modbus,
        "127.0.0.1",
        21502,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "Modbus scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "modbus");
    assert_eq!(r["protocol"], "modbus_tcp");
    assert_eq!(r["port"], 21502);
    let out = collect_out(&lines);
    assert!(out.contains("[+]"), "expected success prefix in output:\n{out}");
}

// ── EtherNet/IP ───────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/eip_sim.py on port 34818"]
fn ops_enip_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/eip_sim.py", "--host", "127.0.0.1", "--port", "34818"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Enip,
        "127.0.0.1",
        34818,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "EtherNet/IP scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "rockwell");
    assert_eq!(r["protocol"], "ethernet_ip");
    assert_eq!(r["port"], 34818);
}

// ── Siemens S7 ────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/siemens_sim.py on port 11202"]
fn ops_siemens_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/siemens_sim.py", "--host", "127.0.0.1", "--port", "11202"]);
    std::thread::sleep(Duration::from_millis(500));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Siemens,
        "127.0.0.1",
        11202,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "Siemens scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "siemens");
    assert_eq!(r["protocol"], "s7comm");
    assert_eq!(r["port"], 11202);
}

// ── Beckhoff ADS ─────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/beckhoff_sim.py on port 38898"]
fn ops_beckhoff_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/beckhoff_sim.py", "--host", "127.0.0.1", "--ads-port", "38898", "--discovery-port", "38899"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Beckhoff,
        "127.0.0.1",
        38898,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "Beckhoff scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "beckhoff");
    assert_eq!(r["protocol"], "ads");
    assert_eq!(r["port"], 38898);
}

// ── BACnet/IP ─────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires scripts/sim_bacnet.py on port 47909"]
fn ops_bacnet_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["scripts/sim_bacnet.py", "--host", "127.0.0.1", "--port", "47909"]);
    std::thread::sleep(Duration::from_millis(600)); // UDP sim needs extra time

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Bacnet,
        "127.0.0.1",
        47909,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "BACnet scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "bacnet");
    assert_eq!(r["protocol"], "bacnet_ip");
    assert_eq!(r["port"], 47909);
    assert!(r["instance_id"].is_number());
}

// ── Mitsubishi SLMP ───────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/slmp_sim.py on port 25007"]
fn ops_mitsubishi_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/slmp_sim.py", "--host", "127.0.0.1", "--port", "25007"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Mitsubishi,
        "127.0.0.1",
        25007,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "Mitsubishi scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "mitsubishi");
    assert_eq!(r["protocol"], "slmp");
    assert_eq!(r["port"], 25007);
}

// ── Omron FINS ────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/fins_sim.py on port 29600"]
fn ops_omron_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/fins_sim.py", "--host", "127.0.0.1", "--port", "29600"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Omron,
        "127.0.0.1",
        29600,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "Omron FINS scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "omron");
    assert_eq!(r["protocol"], "fins");
    assert_eq!(r["port"], 29600);
    assert!(r["model"].is_string());
}

// ── IEC 60870-5-104 ───────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/iec104_sim.py on port 22404"]
fn ops_iec104_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/iec104_sim.py", "--host", "127.0.0.1", "--port", "22404"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Iec104,
        "127.0.0.1",
        22404,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "IEC-104 scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "iec104");
    assert_eq!(r["protocol"], "iec60870_5_104");
    assert_eq!(r["port"], 22404);
}

// ── Phoenix Contact ───────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/phoenix_sim.py on port 21962"]
fn ops_phoenix_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/phoenix_sim.py", "--host", "127.0.0.1", "--port", "21962"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Phoenix,
        "127.0.0.1",
        21962,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "Phoenix scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "phoenix");
    assert_eq!(r["protocol"], "proconos");
    assert_eq!(r["port"], 21962);
    assert!(r["plc_type"].is_string());
}

// ── eWON ─────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/ewon_sim.py on port 18080"]
fn ops_ewon_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/ewon_sim.py", "--host", "127.0.0.1", "--port", "18080"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Ewon,
        "127.0.0.1",
        18080,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "eWON scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "ewon");
    assert_eq!(r["protocol"], "ewon_ipconf");
}

// ── SNMP ──────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/snmp_sim.py on port 21161"]
fn ops_snmp_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/snmp_sim.py", "--host", "127.0.0.1", "--port", "21161"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Snmp,
        "127.0.0.1",
        21161,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "SNMP scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "snmp");
    assert_eq!(r["protocol"], "snmp");
    assert_eq!(r["port"], 21161);
    assert!(r["community"].is_string());
}

// ── MQTT ──────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/mqtt_sim.py on port 21883"]
fn ops_mqtt_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/mqtt_sim.py", "--host", "127.0.0.1", "--port", "21883"]);
    std::thread::sleep(Duration::from_millis(600));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Mqtt,
        "127.0.0.1",
        21883,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "MQTT scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "mqtt");
    assert_eq!(r["protocol"], "mqtt");
    assert_eq!(r["port"], 21883);
    assert!(r["anonymous"].is_boolean());
}

// ── DNP3 ─────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/dnp3_sim.py on port 33001"]
fn ops_dnp3_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/dnp3_sim.py", "--host", "127.0.0.1", "--port", "33001"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Dnp3,
        "127.0.0.1",
        33001,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "DNP3 scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "dnp3");
    assert_eq!(r["protocol"], "dnp3");
    assert_eq!(r["port"], 33001);
    assert!(r["outstation"].is_number());
}

// ── OPC-UA ────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/opcua_sim.py on port 44840"]
fn ops_opcua_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/opcua_sim.py", "--host", "0.0.0.0", "--port", "44840"]);
    std::thread::sleep(Duration::from_millis(1200)); // asyncua startup is slow

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::OpcUa,
        "127.0.0.1",
        44840,
        10,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "OPC-UA scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "opcua");
    assert_eq!(r["protocol"], "opcua");
    assert_eq!(r["port"], 44840);
    assert!(r["endpoint_count"].is_number());
}

// ── Schneider (Modbus + FC43 identity) ───────────────────────────────────────

#[test]
#[ignore = "requires sim/modbus_sim.py --identity on port 21503"]
fn ops_schneider_scan_high_port() {
    let _guard = SimulatorGuard::spawn("python", &["sim/modbus_sim.py", "--host", "127.0.0.1", "--port", "21503", "--identity"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let result = scadaver::ops::scan_ip(
        Protocol::Schneider,
        "127.0.0.1",
        21503,
        5,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );

    assert!(result.is_some(), "Schneider scan should return Some; output:\n{}", collect_out(&lines));
    let r = result.unwrap();
    assert_eq!(r["vendor"], "schneider");
    assert_eq!(r["protocol"], "modbus_tcp");
    assert_eq!(r["port"], 21503);
}

// ── action_id_from_name ───────────────────────────────────────────────────────

#[test]
fn ops_action_id_from_name_known_ids() {
    assert_eq!(scadaver::ops::action_id_from_name("beckhoff/info"), "beckhoff/0");
    assert_eq!(scadaver::ops::action_id_from_name("beckhoff/reboot"), "beckhoff/3");
    assert_eq!(scadaver::ops::action_id_from_name("siemens/cpu_state"), "siemens/0");
    assert_eq!(scadaver::ops::action_id_from_name("siemens/write_db"), "siemens/7");
    assert_eq!(scadaver::ops::action_id_from_name("modbus/map-quick"), "modbus/0");
    assert_eq!(scadaver::ops::action_id_from_name("modbus/map_quick"), "modbus/0");
    assert_eq!(scadaver::ops::action_id_from_name("modicon/write_coil"), "modbus/8");
    assert_eq!(scadaver::ops::action_id_from_name("omron/info"), "omron/0");
    assert_eq!(scadaver::ops::action_id_from_name("snmp/sys_info"), "snmp/0");
    assert_eq!(scadaver::ops::action_id_from_name("iec104/gi"), "iec104/0");
    assert_eq!(scadaver::ops::action_id_from_name("dnp3/attrs"), "dnp3/0");
    assert_eq!(scadaver::ops::action_id_from_name("opcua/info"), "opcua/0");
}

#[test]
fn ops_action_id_from_name_passthrough() {
    // Already-numeric IDs and unknown IDs pass through unchanged.
    assert_eq!(scadaver::ops::action_id_from_name("beckhoff/0"), "beckhoff/0");
    assert_eq!(scadaver::ops::action_id_from_name("siemens/3"), "siemens/3");
    assert_eq!(scadaver::ops::action_id_from_name("common/shellshock"), "common/shellshock");
    assert_eq!(scadaver::ops::action_id_from_name("unknown/thing"), "unknown/thing");
    // Leading slash is stripped before matching.
    assert_eq!(scadaver::ops::action_id_from_name("/beckhoff/info"), "beckhoff/0");
}

// ── run_action smoke tests ────────────────────────────────────────────────────

#[test]
#[ignore = "requires sim/siemens_sim.py on port 11202"]
fn ops_run_action_siemens_cpu_state() {
    let _guard = SimulatorGuard::spawn("python", &["sim/siemens_sim.py", "--host", "127.0.0.1", "--port", "11202"]);
    std::thread::sleep(Duration::from_millis(500));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let ok = scadaver::ops::run_action(
        "siemens/0",
        "127.0.0.1",
        11202,
        "",
        None,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );
    assert!(ok, "run_action siemens/0 should match; output:\n{}", collect_out(&lines));
}

#[test]
#[ignore = "requires sim/modbus_sim.py on port 21502"]
fn ops_run_action_modbus_map_quick() {
    let _guard = SimulatorGuard::spawn("python", &["sim/modbus_sim.py", "--host", "127.0.0.1", "--port", "21502"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let ok = scadaver::ops::run_action(
        "modbus/0",
        "127.0.0.1",
        21502,
        "",
        None,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );
    assert!(ok, "run_action modbus/0 should match; output:\n{}", collect_out(&lines));
}

#[test]
#[ignore = "requires sim/snmp_sim.py on port 21161"]
fn ops_run_action_snmp_sys_info() {
    let _guard = SimulatorGuard::spawn("python", &["sim/snmp_sim.py", "--host", "127.0.0.1", "--port", "21161"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let ok = scadaver::ops::run_action(
        "snmp/0",
        "127.0.0.1",
        21161,
        "",
        None,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );
    assert!(ok, "run_action snmp/0 should match; output:\n{}", collect_out(&lines));
}

#[test]
#[ignore = "requires sim/beckhoff_sim.py on port 38898"]
fn ops_run_action_beckhoff_info() {
    let _guard = SimulatorGuard::spawn("python", &["sim/beckhoff_sim.py", "--host", "127.0.0.1", "--ads-port", "38898", "--discovery-port", "38899"]);
    std::thread::sleep(Duration::from_millis(400));

    let lines = std::sync::Mutex::new(Vec::<String>::new());
    let ok = scadaver::ops::run_action(
        "beckhoff/0",
        "127.0.0.1",
        38898,
        "",
        None,
        &|s| lines.lock().unwrap().push(s.to_string()),
    );
    assert!(ok, "run_action beckhoff/0 should match; output:\n{}", collect_out(&lines));
}
