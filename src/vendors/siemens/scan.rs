use anyhow::Result;

use crate::vendors::siemens::s7comm::{get_device_snapshot, tcp_scan, S7_PORT};

#[derive(Debug, Clone)]
pub struct SiemensDevice {
    pub ip: String,
    pub hardware: Option<String>,
    pub firmware: Option<String>,
    pub cpu_state: Option<String>,
    pub open_ports: Vec<u16>,
}

/// Probe a single IP for a Siemens S7 device.
pub fn scan_ip(ip: &str) -> Result<SiemensDevice> {
    let open_ports = tcp_scan(ip);
    let (hardware, firmware, cpu_state) = if open_ports.contains(&S7_PORT) {
        let (hw, fw, state) = get_device_snapshot(ip, S7_PORT, 5);
        let cpu = if state == "Unknown" { None } else { Some(state) };
        (hw, fw, cpu)
    } else {
        (None, None, None)
    };

    Ok(SiemensDevice {
        ip: ip.to_string(),
        hardware,
        firmware,
        cpu_state,
        open_ports,
    })
}

pub fn print_device(d: &SiemensDevice) {
    println!("  {} — Siemens", d.ip);
    if let Some(hw) = &d.hardware {
        println!("    HW: {hw}, FW: {}", d.firmware.as_deref().unwrap_or("?"));
    }
    if let Some(cpu) = &d.cpu_state {
        println!("    CPU: {cpu}");
    }
    if !d.open_ports.is_empty() {
        let ports: Vec<String> = d.open_ports.iter().map(|p| p.to_string()).collect();
        println!("    Ports: {}", ports.join(", "));
    }
}
