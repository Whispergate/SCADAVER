use crate::vendors::siemens::s7comm::{get_device_snapshot, tcp_scan, S7_PORT};

/// A scanned Siemens S7 PLC: its open ports plus hardware, firmware, and CPU state where readable.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "macros", derive(scadaver_macros::IntoDeviceInfo))]
#[cfg_attr(feature = "macros", vendor(slug = "siemens", scadaver = "crate"))]
pub struct SiemensDevice {
    #[cfg_attr(feature = "macros", device_info(ip))]
    pub ip: String,
    #[cfg_attr(feature = "macros", device_info(optional))]
    pub hardware: Option<String>,
    #[cfg_attr(feature = "macros", device_info(optional))]
    pub firmware: Option<String>,
    #[cfg_attr(feature = "macros", device_info(optional))]
    pub cpu_state: Option<String>,
    #[cfg_attr(feature = "macros", device_info(skip))]
    pub open_ports: Vec<u16>,
}

/// Scan a single IP for a Siemens S7 PLC over S7comm, reading its identity snapshot when reachable.
/// Pass `port = 0` to use the default S7 port (102).
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

