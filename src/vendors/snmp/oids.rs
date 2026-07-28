// Standard MIB-II system group (RFC 1213)
pub const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
pub const SYS_OBJECT_ID: &str = "1.3.6.1.2.1.1.2.0";
pub const SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
pub const SYS_CONTACT: &str = "1.3.6.1.2.1.1.4.0";
pub const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
pub const SYS_LOCATION: &str = "1.3.6.1.2.1.1.6.0";

// IF-MIB interface table (RFC 2863)
pub const IF_TABLE: &str = "1.3.6.1.2.1.2.2";
// Columns within IF_TABLE.1.<col>.<instance>
pub const IF_COL_DESCR: u32 = 2;
pub const IF_COL_SPEED: u32 = 5;
pub const IF_COL_PHYS_ADDR: u32 = 6;
pub const IF_COL_OPER_STATUS: u32 = 8;
pub const IF_COL_IN_ERRORS: u32 = 14;
pub const IF_COL_OUT_ERRORS: u32 = 20;

// IP-MIB tables (RFC 4293)
pub const IP_ADDR_TABLE: &str = "1.3.6.1.2.1.4.20";
pub const IP_ROUTE_TABLE: &str = "1.3.6.1.2.1.4.21";
pub const IP_ARP_TABLE: &str = "1.3.6.1.2.1.4.22";

// Vendor enterprise OID roots
pub const SIEMENS_ROOT: &str = "1.3.6.1.4.1.4329";
pub const SCHNEIDER_ROOT: &str = "1.3.6.1.4.1.3833";
pub const APC_ROOT: &str = "1.3.6.1.4.1.318";
pub const ROCKWELL_ROOT: &str = "1.3.6.1.4.1.1432";
pub const PHOENIX_ROOT: &str = "1.3.6.1.4.1.672";
pub const BECKHOFF_ROOT: &str = "1.3.6.1.4.1.33832";

// APC/Schneider UPS PowerNet-MIB (1.3.6.1.4.1.318.1.1.1.*)
pub const APC_MODEL: &str = "1.3.6.1.4.1.318.1.1.1.1.1.1.0";
pub const APC_FIRMWARE: &str = "1.3.6.1.4.1.318.1.1.1.1.2.1.0";
pub const APC_SERIAL: &str = "1.3.6.1.4.1.318.1.1.1.1.2.3.0";
pub const APC_BATTERY_STATUS: &str = "1.3.6.1.4.1.318.1.1.1.2.1.1.0";
pub const APC_RUNTIME_MINS: &str = "1.3.6.1.4.1.318.1.1.1.2.2.3.0";
pub const APC_INPUT_VOLTAGE: &str = "1.3.6.1.4.1.318.1.1.1.3.2.1.0";
pub const APC_OUTPUT_LOAD_PCT: &str = "1.3.6.1.4.1.318.1.1.1.4.2.3.0";
pub const APC_OUTPUT_STATUS: &str = "1.3.6.1.4.1.318.1.1.1.4.1.1.0";
// SET to 2 (graceful off) to shut down connected equipment via UPS — highly destructive
pub const APC_CMD_GRACEFUL_OFF: &str = "1.3.6.1.4.1.318.1.1.1.5.2.3.0";

/// Resolve sysObjectID prefix to an ICS vendor slug.
pub fn vendor_from_sys_oid(oid: &str) -> Option<&'static str> {
    if oid.starts_with(SIEMENS_ROOT) {
        Some("siemens")
    } else if oid.starts_with(SCHNEIDER_ROOT) || oid.starts_with(APC_ROOT) {
        Some("schneider")
    } else if oid.starts_with(ROCKWELL_ROOT) {
        Some("rockwell")
    } else if oid.starts_with(PHOENIX_ROOT) {
        Some("phoenix")
    } else if oid.starts_with(BECKHOFF_ROOT) {
        Some("beckhoff")
    } else {
        None
    }
}

pub const COMMON_COMMUNITIES: &[&str] = &[
    "public", "private", "community", "snmp", "admin", "manager",
    "read", "write", "secret", "monitor", "test",
];
