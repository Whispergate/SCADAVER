use super::fins::{self, FinsDevice};

/// Probe a single IP for an Omron FINS device (UDP then TCP fallback).
pub fn scan_ip(ip: &str) -> Option<FinsDevice> {
    // Try UDP first (no connection overhead)
    if let Some(dev) = fins::scan_udp(ip) {
        return Some(dev);
    }
    // Fall back to TCP
    fins::get_device_info_tcp(ip).ok()
}
