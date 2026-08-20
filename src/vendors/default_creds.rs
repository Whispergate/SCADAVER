//! Vendor-specific default credentials curated from public ICS/SCADA research.
//!
//! Sources: `SecLists` SCADA passwords, SCADAPASS project, digitalsubstation.com,
//! and documented factory defaults from vendor advisories.

/// Common ICS/SCADA HTTP Basic Auth default credentials.
///
/// Sources: SCADAPASS project, vendor documentation, ICS-CERT advisories.
/// Ordered from most-commonly-seen to least.
pub const ICS_HTTP_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "password"),
    ("administrator", "administrator"),
    ("administrator", ""),
    ("user", "user"),
    ("guest", "guest"),
    ("operator", "operator"),
    ("root", "root"),
    ("root", ""),
    ("admin", "1234"),
    ("admin", "admin123"),
    ("supervisor", "supervisor"),
    // Phoenix Contact WebVisit / Schneider M340 / Unity Pro factory default
    ("USER", "USER"),
    ("USER", ""),
    ("ADMIN", "ADMIN"),
    // eWON factory default
    ("admin", "private"),
    // Siemens SINEMA / S7-1200 web server
    ("service", "service"),
    // Beckhoff WebControl
    ("Administrator", ""),
    ("guest", ""),
    // Mitsubishi / Generic HMI
    ("mitsubishi", "mitsubishi"),
    ("plc", "plc"),
    ("operator", "operator1"),
    // Beckhoff TwinCAT
    ("Administrator", "1"),
    ("admin", "beckhoff"),
    // Schneider viewer
    ("viewer", ""),
    // ABB
    ("Admin", "Admin"),
    ("engineer", "engineer"),
    ("admin", "abb"),
    // GE
    ("admin", "ge"),
    ("engineer", "ge123"),
    // Emerson DeltaV
    ("admin", "emerson"),
    ("DeltaV", "DeltaV"),
    ("admin", "deltav"),
    // Honeywell
    ("admin", "honeywell"),
    ("engineer", "Honeywell"),
    ("admin", "Honey1"),
    // Rockwell
    ("admin", "1756"),
    ("admin", "rockwell"),
    // Phoenix Contact alternate
    ("admin", "phoenix"),
    // General ICS operator accounts
    ("operator", ""),
    ("technician", "technician"),
    ("maintenance", "maintenance"),
    ("config", "config"),
    ("eng", "eng"),
    ("user", "1234"),
    ("admin", "system"),
];

/// `S7Comm` PLC access-protection passwords (no username: password only).
/// Ordered by frequency observed in the wild.
pub const SIEMENS_S7_PASSWORDS: &[&str] = &[
    "",           // no protection (most common factory default)
    "password",
    "admin",
    "1234",
    "12345",
    "123456",
    "siemens",
    "SIMATIC",
    "s7300",
    "s71200",
    "s71500",
    "tia",
    "TIA",
    "abc",
    "ADMIN",
    "111",
    "0",
    "user",
    "aaaa",
    "bbbb",
    "cccc",
    "dddd",
    "eeee",
    "ffff",
    // Additional common S7/TIA Portal passwords
    "S7",
    "plc",
    "PLC",
    "wincc",
    "WinCC",
    "Password1",
    "Siemens1",
    "Admin",
    "simatic",
    "s7online",
    "s7comm",
    "step7",
    "Step7",
    "siplus",
    "logo",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ics_http_creds_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for &pair in ICS_HTTP_CREDS {
            assert!(seen.insert(pair), "duplicate entry: ({:?}, {:?})", pair.0, pair.1);
        }
    }

    #[test]
    fn siemens_passwords_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for &pw in SIEMENS_S7_PASSWORDS {
            assert!(seen.insert(pw), "duplicate password: {pw:?}");
        }
    }
}

