//! Vendor-specific default credentials curated from public ICS/SCADA research.
//!
//! Sources: `SecLists` SCADA passwords, SCADAPASS project, digitalsubstation.com,
//! and documented factory defaults from vendor advisories.

/// `S7Comm` PLC access-protection passwords (no username — password only).
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

