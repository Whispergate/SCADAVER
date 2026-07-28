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
pub fn scan_ip(ip: &str) -> SiemensDevice {
    scan_ip_with_port(ip, S7_PORT)
}

pub fn scan_ip_with_port(ip: &str, port: u16) -> SiemensDevice {
    let port = if port == 0 { S7_PORT } else { port };
    let open_ports = tcp_scan(ip);
    let mut open_ports = open_ports;
    if port != S7_PORT && crate::vendors::siemens::s7comm::scan_port(ip, port) {
        open_ports.push(port);
        open_ports.sort_unstable();
        open_ports.dedup();
    }
    let (hardware, firmware, cpu_state) = if open_ports.contains(&port) {
        let (hw, fw, state) = get_device_snapshot(ip, port, 5);
        let cpu = if state == "Unknown" {
            None
        } else {
            Some(state)
        };
        (hw, fw, cpu)
    } else {
        (None, None, None)
    };

    SiemensDevice {
        ip: ip.to_string(),
        hardware,
        firmware,
        cpu_state,
        open_ports,
    }
}

