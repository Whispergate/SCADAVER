use anyhow::Result;
use std::collections::HashMap;

use super::client::{self, SnmpValue};
use super::oids;

// ─── Structs ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    pub descr: String,
    pub object_id: String,
    pub name: String,
    pub contact: String,
    pub location: String,
    pub uptime_secs: u64,
    pub community: String,
    pub ics_vendor: Option<&'static str>,
    pub is_apc_ups: bool,
}

#[derive(Debug, Clone)]
pub struct Interface {
    pub index: u32,
    pub descr: String,
    pub mac: String,
    pub speed_mbps: u64,
    pub admin_up: bool,
    pub oper_up: bool,
    pub in_errors: u64,
    pub out_errors: u64,
}

#[derive(Debug, Clone)]
pub struct CveHit {
    pub id: &'static str,
    pub cvss: &'static str,
    pub summary: &'static str,
    pub ref_url: &'static str,
}

// ─── Enumeration ─────────────────────────────────────────────────────────────

pub fn get_system_info(ip: &str, port: u16, community: &str) -> Result<SystemInfo> {
    let scalar_oids = [
        oids::SYS_DESCR,
        oids::SYS_OBJECT_ID,
        oids::SYS_UPTIME,
        oids::SYS_CONTACT,
        oids::SYS_NAME,
        oids::SYS_LOCATION,
    ];
    let results = client::get_multi(ip, port, community, &scalar_oids)?;
    let at = |i: usize| results.get(i).map(|(_, v)| v.display()).unwrap_or_default();
    let uptime_ticks: u64 = results
        .get(2)
        .and_then(|(_, v)| v.as_int())
        .map(|n| n as u64)
        .unwrap_or(0);
    let object_id = at(1);
    let ics_vendor = oids::vendor_from_sys_oid(&object_id);
    let is_apc_ups = object_id.starts_with(oids::APC_ROOT);
    Ok(SystemInfo {
        descr: at(0),
        object_id,
        uptime_secs: uptime_ticks / 100,
        contact: at(3),
        name: at(4),
        location: at(5),
        community: community.to_string(),
        ics_vendor,
        is_apc_ups,
    })
}

/// Walk IF-MIB ifTable and return per-interface summaries.
pub fn get_interfaces(ip: &str, port: u16, community: &str) -> Result<Vec<Interface>> {
    let entries = client::walk(ip, port, community, oids::IF_TABLE)?;
    // OID: ifTable.1.<col>.<instance>  →  root arcs = 9, col at [9], inst at [10]
    let root_len = 9usize;
    let mut cols: HashMap<u32, HashMap<u32, SnmpValue>> = HashMap::new();
    for (oid_str, val) in entries {
        let arcs: Vec<u32> = oid_str
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        if arcs.len() < root_len + 2 {
            continue;
        }
        let col = arcs[root_len];
        let inst = arcs[root_len + 1];
        cols.entry(col).or_default().insert(inst, val);
    }
    let instances: std::collections::BTreeSet<u32> = cols
        .values()
        .flat_map(|m| m.keys().copied())
        .collect();
    let get = |col: u32, inst: u32| -> Option<&SnmpValue> { cols.get(&col)?.get(&inst) };
    let int_val = |col: u32, inst: u32| -> u64 {
        get(col, inst).and_then(|v| v.as_int()).map(|n| n as u64).unwrap_or(0)
    };

    let mut result = Vec::new();
    for inst in instances {
        let mac = get(oids::IF_COL_PHYS_ADDR, inst)
            .and_then(|v| v.as_bytes())
            .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"))
            .unwrap_or_default();
        let speed_bps = int_val(oids::IF_COL_SPEED, inst);
        result.push(Interface {
            index: inst,
            descr: get(oids::IF_COL_DESCR, inst)
                .map(|v| v.display())
                .unwrap_or_default(),
            mac,
            speed_mbps: speed_bps / 1_000_000,
            admin_up: int_val(oids::IF_COL_ADMIN_STATUS, inst) == 1,
            oper_up: int_val(oids::IF_COL_OPER_STATUS, inst) == 1,
            in_errors: int_val(oids::IF_COL_IN_ERRORS, inst),
            out_errors: int_val(oids::IF_COL_OUT_ERRORS, inst),
        });
    }
    Ok(result)
}

/// Walk IP address, route, and ARP tables and return formatted lines.
pub fn get_topology(ip: &str, port: u16, community: &str) -> Result<Vec<String>> {
    let mut lines = Vec::new();

    // IP addresses
    let addrs = client::walk(ip, port, community, oids::IP_ADDR_TABLE)?;
    if !addrs.is_empty() {
        lines.push("  IP addresses:".to_string());
        for (oid, val) in &addrs {
            // ipAdEntAddr column is .1, ipAdEntNetMask is .3
            if oid.contains(".20.1.1.") {
                lines.push(format!("    {}", val.display()));
            }
        }
    }

    // ARP cache (ipNetToMedia)
    let arp = client::walk(ip, port, community, oids::IP_ARP_TABLE)?;
    let arp_macs: Vec<String> = arp
        .iter()
        .filter(|(o, _)| o.contains(".22.1.2."))
        .map(|(o, v)| {
            let ip_suffix: String = o.splitn(2, ".22.1.2.").nth(1).unwrap_or("").to_string();
            format!("    {} → {}", ip_suffix, v.display())
        })
        .collect();
    if !arp_macs.is_empty() {
        lines.push("  ARP cache:".to_string());
        lines.extend(arp_macs);
    }

    // Routes
    let routes = client::walk(ip, port, community, oids::IP_ROUTE_TABLE)?;
    let route_dests: Vec<String> = routes
        .iter()
        .filter(|(o, _)| o.contains(".21.1.1."))
        .map(|(_, v)| format!("    {}", v.display()))
        .collect();
    if !route_dests.is_empty() {
        lines.push("  Routes (dest):".to_string());
        lines.extend(route_dests);
    }

    Ok(lines)
}

// ─── CVE matching ─────────────────────────────────────────────────────────────

pub fn check_cves(info: &SystemInfo) -> Vec<CveHit> {
    let mut hits = Vec::new();
    let descr = info.descr.to_ascii_lowercase();
    let oid = &info.object_id;
    let community = &info.community;

    if community == "public" || community == "private" {
        hits.push(CveHit {
            id: "CVE-1999-0517",
            cvss: "7.5",
            summary: "Default SNMP community string in use — full read access",
            ref_url: "https://nvd.nist.gov/vuln/detail/CVE-1999-0517",
        });
    }

    if descr.contains("scalance") {
        hits.push(CveHit {
            id: "ICSA-20-042-02",
            cvss: "High",
            summary: "Siemens SCALANCE: crafted SNMP packet → DoS or RCE (CVE-2015-5621 / CVE-2018-18065)",
            ref_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-20-042-02",
        });
        if descr.contains("x200") {
            hits.push(CveHit {
                id: "CVE-2007-5846",
                cvss: "5.0",
                summary: "SCALANCE X200 IRT <V5.5.0: legacy net-snmp integer overflow",
                ref_url: "https://nvd.nist.gov/vuln/detail/CVE-2007-5846",
            });
        }
    }

    if descr.contains("scalance s") || descr.contains("cp 343") || descr.contains("cp 443")
        || oid.starts_with(oids::SIEMENS_ROOT)
    {
        hits.push(CveHit {
            id: "CVE-2021-41991",
            cvss: "7.5",
            summary: "Siemens SIMATIC NET CP / SINEMA / SCALANCE: unauthenticated remote (ICSA-25-259-03)",
            ref_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-25-259-03",
        });
    }

    if descr.contains("scalance s602") || descr.contains("scalance s612")
        || descr.contains("scalance s623") || descr.contains("scalance s627")
    {
        hits.push(CveHit {
            id: "CVE-2013-3634",
            cvss: "7.3",
            summary: "SCALANCE S602/S612/S623/S627-2M: auth bypass — execute SNMP without valid creds",
            ref_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-13-149-01",
        });
    }

    if info.is_apc_ups || oid.starts_with(oids::APC_ROOT) {
        hits.push(CveHit {
            id: "APC-ADVISORY",
            cvss: "N/A",
            summary: "APC/Schneider UPS: write community 'private' → graceful shutdown command available",
            ref_url: "https://www.cisa.gov/news-events/ics-advisories",
        });
    }

    hits
}
