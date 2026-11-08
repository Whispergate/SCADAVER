//! Omron FINS/TCP: node address negotiation, then a controller data read (05 01).
//!
//! The legacy arm printed node, model and version and returned `None` on any error, so a
//! surface could not tell a refused connection from a device that answered short. casket
//! still treats a short reply as success and fills `"Unknown"` instead of failing.
//!
//! DM access, CPU status and CPU mode changes live here too, for the reason the eWON registers
//! do: every surface resolved `port == 0` to 9600 by itself, and casket's errors read "FINS
//! read DM: response too short", which names neither the endpoint nor the range.

// The surfaces still render the legacy reporting path; phase 3 calls this.
#![allow(dead_code)]

use crate::model::{EndpointRecord, Level, Outcome};
use crate::protocol::Protocol;
use casket::vendors::omron::fins;
use std::collections::BTreeMap;

/// A FINS node address of 0 means "whichever server node the address negotiation assigned".
pub const SERVER_ASSIGNED_NODE: u8 = 0;

/// Resolve a user-supplied port to the one the request will use. Port 0 means FINS/TCP 9600.
#[must_use]
pub fn fins_port(port: u16) -> u16 {
    if port == 0 {
        Protocol::Omron.default_port()
    } else {
        port
    }
}

/// One inclusive run of DM words, rejected at construction when it cannot exist on the wire.
///
/// This exists so no surface has to compute `start + count - 1` itself: with `start = 65530`
/// and `count = 32` that sum overflows a `u16`, which panics in a debug build and wraps into a
/// nonsense address in release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmRange {
    pub start: u16,
    pub count: u16,
}

impl DmRange {
    /// Build a range, or explain why it is not addressable.
    pub fn new(start: u16, count: u16) -> Result<Self, String> {
        if count == 0 {
            return Err("Omron DM access needs a count of at least 1 word".to_string());
        }
        let last = u32::from(start) + u32::from(count - 1);
        if u16::try_from(last).is_err() {
            return Err(format!(
                "Omron DM range DM{start} plus {count} word(s) runs past DM65535"
            ));
        }
        Ok(Self { start, count })
    }

    /// Last address in the range. Safe by construction: `new` rejected anything past DM65535,
    /// and `count - 1` (not `start + count - 1`) keeps DM65535 + 1 word from overflowing first.
    #[must_use]
    pub fn last(self) -> u16 {
        self.start + (self.count - 1)
    }

    /// `DM100` for a single word, `DM100..DM131` otherwise, so messages read the way a user
    /// typed the request.
    #[must_use]
    pub fn label(self) -> String {
        if self.count == 1 {
            format!("DM{}", self.start)
        } else {
            format!("DM{}..DM{}", self.start, self.last())
        }
    }
}

/// Probe one host. `port = 0` means the registered default. `get_device_info_tcp` owns its
/// own connect and read timing (a five second constant), so `_timeout` is accepted for a
/// uniform dispatch signature and ignored here on purpose.
pub fn scan_ip(ip: &str, port: u16, _timeout: u64) -> Outcome {
    let effective_port = fins_port(port);
    let mut outcome = Outcome::default();

    let device = match fins::get_device_info_tcp(ip, effective_port) {
        Ok(device) => device,
        Err(error) => {
            outcome.say(
                Level::Warn,
                format!("No Omron FINS response from {ip}:{effective_port}: {error}"),
            );
            return outcome;
        }
    };

    let mut fields = BTreeMap::new();
    fields.insert("node".to_string(), serde_json::json!(device.node_addr));
    fields.insert("model".to_string(), serde_json::json!(device.model));
    fields.insert("version".to_string(), serde_json::json!(device.version));
    fields.insert("fins_port".to_string(), serde_json::json!(effective_port));

    let identity = Some(device.model.clone()).filter(|model| !model.is_empty());

    outcome.records.push(EndpointRecord {
        ip: ip.to_string(),
        port: effective_port,
        protocol: Protocol::Omron,
        vendor: "omron".to_string(),
        identity,
        fields,
    });
    outcome.say(
        Level::Success,
        format!("Omron FINS device on {ip}:{effective_port}."),
    );

    outcome
}

// ---------------------------------------------------------------------------
// Live reads and writes.
//
// Each one owns the socket call and the port resolution, and every error names the
// operation, the range and the endpoint. Nothing here prints; the caller renders.
// ---------------------------------------------------------------------------

/// What the controller reported about itself: model, version and the server node it assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub model: String,
    pub version: String,
    pub node: u8,
}

/// Read the controller identity (command 05 01) and the negotiated node address.
pub fn identity(ip: &str, port: u16) -> Result<Identity, String> {
    let port = fins_port(port);
    let device = fins::get_device_info_tcp(ip, port)
        .map_err(|error| format!("Omron FINS controller read from {ip}:{port} failed: {error}"))?;
    Ok(Identity {
        model: device.model,
        version: device.version,
        node: device.node_addr,
    })
}

/// Read `count` DM words starting at `start`.
///
/// A short answer is an error, not a smaller success: a caller that asked for 32 words and
/// got 3 has no way to tell a truncated reply from a device whose DM area ends there, and the
/// old code rendered the two identically.
pub fn read_dm_words(ip: &str, port: u16, start: u16, count: u16) -> Result<Vec<u16>, String> {
    let range = DmRange::new(start, count)?;
    let port = fins_port(port);
    let words = fins::read_dm_words(ip, port, SERVER_ASSIGNED_NODE, range.start, range.count)
        .map_err(|error| {
            format!(
                "Omron FINS read of {} from {ip}:{port} failed: {error}",
                range.label()
            )
        })?;
    if words.len() != usize::from(range.count) {
        return Err(format!(
            "Omron FINS read of {} from {ip}:{port} returned {} of {} word(s)",
            range.label(),
            words.len(),
            range.count
        ));
    }
    Ok(words)
}

/// Write `values` into DM words starting at `start`.
///
/// An empty slice is refused here rather than sent as a zero-length memory-area write, which
/// most controllers answer with an end code that says nothing useful.
pub fn write_dm_words(ip: &str, port: u16, start: u16, values: &[u16]) -> Result<(), String> {
    if values.is_empty() {
        return Err("Omron DM write needs at least one word value".to_string());
    }
    let count = u16::try_from(values.len()).map_err(|_| {
        format!(
            "Omron DM write of {} word(s) at DM{start} exceeds the FINS 65535-word limit",
            values.len()
        )
    })?;
    let range = DmRange::new(start, count)?;
    let port = fins_port(port);
    fins::write_dm_words(ip, port, SERVER_ASSIGNED_NODE, range.start, values).map_err(|error| {
        format!(
            "Omron FINS write of {} to {ip}:{port} failed: {error}",
            range.label()
        )
    })
}

/// Read the CPU operating state (command 06 01) as the documented name: Run, Stop, Monitor,
/// Program or Unknown.
pub fn cpu_state(ip: &str, port: u16) -> Result<String, String> {
    let port = fins_port(port);
    fins::get_cpu_state(ip, port, SERVER_ASSIGNED_NODE)
        .map_err(|error| format!("Omron FINS CPU status read from {ip}:{port} failed: {error}"))
}

/// A CPU operating mode a surface may ask for (command 04 01).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuMode {
    Run,
    Stop,
    Monitor,
    Program,
}

impl CpuMode {
    /// The mode the user typed, or an error that lists the ones that exist.
    pub fn parse(token: &str) -> Result<Self, String> {
        match token.trim().to_ascii_lowercase().as_str() {
            "run" => Ok(Self::Run),
            "stop" => Ok(Self::Stop),
            "monitor" => Ok(Self::Monitor),
            "program" => Ok(Self::Program),
            other => Err(format!(
                "Unknown Omron CPU mode '{other}': use run, stop, monitor or program."
            )),
        }
    }

    /// The token `parse` accepts, for messages and help text.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Stop => "stop",
            Self::Monitor => "monitor",
            Self::Program => "program",
        }
    }

    /// casket's spelling of the same wire byte.
    fn wire(self) -> fins::CpuMode {
        match self {
            Self::Run => fins::CpuMode::Run,
            Self::Stop => fins::CpuMode::Stop,
            Self::Monitor => fins::CpuMode::Monitor,
            Self::Program => fins::CpuMode::Program,
        }
    }
}

/// Change the CPU operating mode and treat a refused change as a failure.
///
/// casket returns `Ok(false)` when the controller answers with a non-zero end code, so a
/// caller using `?` reads a rejection as success. That is the bug this wrapper exists for.
pub fn set_cpu_mode(ip: &str, port: u16, mode: CpuMode) -> Result<(), String> {
    let port = fins_port(port);
    let acknowledged =
        fins::set_cpu_state(ip, port, SERVER_ASSIGNED_NODE, mode.wire()).map_err(|error| {
            format!(
                "Omron FINS CPU mode change to {} on {ip}:{port} failed: {error}",
                mode.as_str()
            )
        })?;
    if !acknowledged {
        return Err(format!(
            "Omron FINS CPU mode change to {} on {ip}:{port} was rejected (non-zero end code)",
            mode.as_str()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_zero_resolves_to_the_fins_tcp_default() {
        assert_eq!(fins_port(0), 9600);
        assert_eq!(fins_port(1502), 1502);
    }

    #[test]
    fn dm_range_rejects_an_empty_span() {
        let error = DmRange::new(0, 0).expect_err("a zero count is not a range");
        assert!(error.contains("at least 1"), "got {error}");
    }

    #[test]
    fn dm_range_rejects_a_span_past_the_last_word() {
        // 65530 + 32 overflows a u16; the old surfaces added `count - 1` themselves.
        let error = DmRange::new(65530, 32).expect_err("DM65530 + 32 words cannot exist");
        assert!(
            error.contains("DM65530") && error.contains("65535"),
            "got {error}"
        );
        assert_eq!(DmRange::new(65535, 1).expect("one word fits").last(), 65535);
    }

    #[test]
    fn dm_range_labels_one_word_and_many() {
        assert_eq!(DmRange::new(100, 1).expect("valid").label(), "DM100");
        assert_eq!(
            DmRange::new(100, 32).expect("valid").label(),
            "DM100..DM131"
        );
        assert_eq!(DmRange::new(0, 32).expect("valid").last(), 31);
    }

    #[test]
    fn cpu_mode_parses_the_documented_tokens() {
        assert_eq!(CpuMode::parse("RUN").expect("valid"), CpuMode::Run);
        assert_eq!(CpuMode::parse(" stop ").expect("valid"), CpuMode::Stop);
        assert_eq!(CpuMode::parse("Monitor").expect("valid"), CpuMode::Monitor);
        assert_eq!(CpuMode::parse("program").expect("valid"), CpuMode::Program);
        for mode in [
            CpuMode::Run,
            CpuMode::Stop,
            CpuMode::Monitor,
            CpuMode::Program,
        ] {
            assert_eq!(CpuMode::parse(mode.as_str()).expect("round trip"), mode);
        }
    }

    #[test]
    fn cpu_mode_parse_names_the_offending_token() {
        let error = CpuMode::parse("flip").expect_err("flip is not a FINS mode");
        assert!(error.contains("'flip'"), "got {error}");
        assert!(
            error.contains("run"),
            "the error lists the valid modes: {error}"
        );
    }
}
