/// Vendor-specific default credentials curated from public ICS/SCADA research.
///
/// Sources: SecLists SCADA passwords, SCADAPASS project, digitalsubstation.com,
/// and documented factory defaults from vendor advisories.

/// S7Comm PLC access-protection passwords (no username — password only).
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

/// Beckhoff ADS route authentication: (username, password) pairs.
/// Beckhoff IPC/Panel PCs often use Windows local accounts.
pub const BECKHOFF_CREDS: &[(&str, &str)] = &[
    ("Administrator", "1"),
    ("Administrator", ""),
    ("Administrator", "admin"),
    ("Administrator", "12345"),
    ("Administrator", "password"),
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "1"),
    ("User", "1"),
    ("Guest", ""),
];

/// Schneider Modicon web interface credentials (username:password).
/// Used for session-based exploits requiring HTTP auth.
pub const SCHNEIDER_CREDS: &[(&str, &str)] = &[
    ("USER", "USER"),
    ("USER", "user"),
    ("admin", "admin"),
    ("admin", ""),
    ("user", "user"),
    ("user", ""),
    ("ADMIN", "ADMIN"),
    ("viewer", ""),
    ("operator", "operator"),
];

/// Phoenix Contact web/ProConOS credentials.
pub const PHOENIX_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "1234"),
    ("guest", ""),
    ("user", "user"),
];

/// Returns default passwords for a given vendor (password-only protocols like S7Comm).
pub fn default_passwords_for(vendor: &str) -> &'static [&'static str] {
    match vendor.to_lowercase().as_str() {
        "siemens" => SIEMENS_S7_PASSWORDS,
        _ => &[],
    }
}

/// Returns default username:password pairs for a given vendor.
pub fn default_creds_for(vendor: &str) -> &'static [(&'static str, &'static str)] {
    match vendor.to_lowercase().as_str() {
        "beckhoff" => BECKHOFF_CREDS,
        "schneider" | "modicon" => SCHNEIDER_CREDS,
        "phoenix" => PHOENIX_CREDS,
        _ => &[],
    }
}
