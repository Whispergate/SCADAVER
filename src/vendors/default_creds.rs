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

