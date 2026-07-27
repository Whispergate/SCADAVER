use anyhow::Result;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use crate::core::bytes::{get_netid_as_string, ip_to_hex, reverse_bytes};
use crate::core::network::NetworkInterface;
use crate::vendors::beckhoff::ads::{
    build_local_netid, construct_ams_packet, decode_ads_value, parse_ads_response,
    parse_ams_response, AdsParams,
};

const DISCOVERY_PORT: u16 = 48899;
pub const DEFAULT_ADS_PORT: u16 = 48898;

#[derive(Debug, Clone)]
pub struct BeckhoffDevice {
    pub ip: String,
    pub name: String,
    pub netid: String,
    pub netid_str: String,
    pub tc_version: String,
    pub kernel: String,
    pub ssl_thumbprint: Option<String>,
}

fn derived_ads_device(ip: &str, port: u16) -> Option<BeckhoffDevice> {
    ip.parse::<std::net::Ipv4Addr>().ok()?;
    let netid = format!("{}0101", ip_to_hex(ip));
    Some(BeckhoffDevice {
        ip: ip.to_string(),
        name: format!("Beckhoff ADS TCP {}", effective_ads_port(port)),
        netid_str: get_netid_as_string(&netid),
        netid,
        tc_version: "Unknown".to_string(),
        kernel: "Unknown".to_string(),
        ssl_thumbprint: None,
    })
}

fn effective_ads_port(port: u16) -> u16 {
    if port == 0 {
        DEFAULT_ADS_PORT
    } else {
        port
    }
}

fn parse_discovery_frame(data: &[u8], src_ip: &str) -> Option<BeckhoffDevice> {
    let hexdata = hex_encode(data);
    let hexdata = hexdata.as_bytes();

    if hexdata.len() < 56 {
        return None;
    }

    let netid = std::str::from_utf8(&hexdata[24..36]).ok()?;
    let name_len_str = format!(
        "{}{}",
        std::str::from_utf8(&hexdata[54..56]).ok()?,
        std::str::from_utf8(&hexdata[52..54]).ok()?
    );
    let name_len = usize::from_str_radix(&name_len_str, 16).ok()?;

    if data.len() < 27 + name_len {
        return None;
    }
    let name = String::from_utf8_lossy(&data[28..28 + name_len - 1]).to_string();
    if name.is_empty() {
        return None;
    }

    let i = (27 + name_len) * 2 + 18;
    let kernel = if hexdata.len() >= i + 24 {
        let k0 = u32::from_str_radix(
            &reverse_bytes(std::str::from_utf8(&hexdata[i..i + 8]).unwrap_or("00000000")),
            16,
        )
        .unwrap_or(0);
        let k1 = u32::from_str_radix(
            &reverse_bytes(std::str::from_utf8(&hexdata[i + 8..i + 16]).unwrap_or("00000000")),
            16,
        )
        .unwrap_or(0);
        let k2 = u32::from_str_radix(
            &reverse_bytes(std::str::from_utf8(&hexdata[i + 16..i + 24]).unwrap_or("00000000")),
            16,
        )
        .unwrap_or(0);
        format!("{k0}.{k1}.{k2}")
    } else {
        "Unknown".to_string()
    };

    let tc_i = i + 24 + 528;
    let tc_version = if hexdata.len() >= tc_i + 8 {
        let maj = u8::from_str_radix(
            std::str::from_utf8(&hexdata[tc_i..tc_i + 2]).unwrap_or("00"),
            16,
        )
        .unwrap_or(0);
        let min = u8::from_str_radix(
            std::str::from_utf8(&hexdata[tc_i + 2..tc_i + 4]).unwrap_or("00"),
            16,
        )
        .unwrap_or(0);
        let patch = u32::from_str_radix(
            &reverse_bytes(std::str::from_utf8(&hexdata[tc_i + 4..tc_i + 8]).unwrap_or("0000")),
            16,
        )
        .unwrap_or(0);
        format!("{maj}.{min}.{patch}")
    } else {
        "Unknown".to_string()
    };

    // Look for SSL thumbprint
    let ssl_thumbprint = data
        .windows(4)
        .position(|w| w == b"\x12\x00\x41\x00")
        .and_then(|pos| {
            let start = pos + 4;
            data[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|end| String::from_utf8_lossy(&data[start..start + end]).to_uppercase())
        });

    Some(BeckhoffDevice {
        ip: src_ip.to_string(),
        name,
        netid: netid.to_string(),
        netid_str: get_netid_as_string(netid),
        tc_version,
        kernel,
        ssl_thumbprint,
    })
}

/// Broadcast-discover Beckhoff TwinCAT devices.
pub fn discover(
    interface: &NetworkInterface,
    timeout: u64,
    silent: bool,
) -> Result<Vec<BeckhoffDevice>> {
    use crate::core::network::create_udp_broadcast_socket;

    let local_netid = build_local_netid(&interface.ip);
    let sock = create_udp_broadcast_socket(&interface.ip, timeout)?;

    let discovery_pkt = format!("036614710000000001000000{}1027{:08x}", local_netid, 0u32);
    let pkt = hex_decode(&discovery_pkt.replace(' ', ""));
    sock.send_to(&pkt, format!("255.255.255.255:{DISCOVERY_PORT}"))?;

    if !silent {
        println!("Scanning for Beckhoff devices ({timeout}s timeout)...");
    }

    let mut devices = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, addr)) => {
                if let Some(dev) = parse_discovery_frame(&buf[..n], &addr.ip().to_string()) {
                    if !silent {
                        println!(
                            "  {}: {} (NetID: {}, TC: {}, OS: {})",
                            dev.ip, dev.name, dev.netid_str, dev.tc_version, dev.kernel
                        );
                    }
                    devices.push(dev);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => break,
        }
    }

    if devices.is_empty() && !silent {
        println!("No Beckhoff devices found.");
    }

    Ok(devices)
}

/// Send discovery to a specific IP address.
pub fn discover_ip(ip: &str, timeout: u64, silent: bool) -> Result<Vec<BeckhoffDevice>> {
    use crate::core::network::local_ip_for;

    let local_ip = local_ip_for(ip);
    let local_netid = build_local_netid(&local_ip);

    let sock =
        UdpSocket::bind(format!("{local_ip}:0")).or_else(|_| UdpSocket::bind("0.0.0.0:0"))?;
    sock.set_read_timeout(Some(Duration::from_secs(timeout)))?;

    let discovery_pkt = format!("036614710000000001000000{local_netid}1027{:08x}", 0u32);
    let pkt = hex_decode(&discovery_pkt.replace(' ', ""));
    sock.send_to(&pkt, format!("{ip}:{DISCOVERY_PORT}"))?;

    let mut buf = [0u8; 1024];
    let (n, addr) = match sock.recv_from(&mut buf) {
        Ok(v) => v,
        Err(_) => {
            if !silent {
                println!("No Beckhoff response from {ip}");
            }
            return Ok(vec![]);
        }
    };

    let dev = match parse_discovery_frame(&buf[..n], &addr.ip().to_string()) {
        Some(d) => d,
        None => return Ok(vec![]),
    };

    if !silent {
        println!(
            "  {}: {} (NetID: {}, TC: {}, OS: {})",
            dev.ip, dev.name, dev.netid_str, dev.tc_version, dev.kernel
        );
    }
    Ok(vec![dev])
}

/// Target a Beckhoff device by UDP discovery first, then fall back to ADS/TCP.
/// Pass `port = 0` to use the default ADS port (48898).
pub fn discover_ip_with_port(
    ip: &str,
    timeout: u64,
    silent: bool,
    port: u16,
) -> Result<Vec<BeckhoffDevice>> {
    let udp = discover_ip(ip, timeout, true)?;
    if !udp.is_empty() {
        if !silent {
            for dev in &udp {
                println!(
                    "  {}: {} (NetID: {}, TC: {}, OS: {})",
                    dev.ip, dev.name, dev.netid_str, dev.tc_version, dev.kernel
                );
            }
        }
        return Ok(udp);
    }

    let Some(dev) = derived_ads_device(ip, port) else {
        if !silent {
            println!("No Beckhoff response from {ip}");
        }
        return Ok(vec![]);
    };

    let local_netid = build_local_netid(&crate::core::network::local_ip_for(ip));
    let state = get_state(&dev, &local_netid, port);
    if state == "ERROR" {
        if !silent {
            println!("No Beckhoff UDP discovery or ADS TCP response from {ip}");
        }
        return Ok(vec![]);
    }

    if !silent {
        println!(
            "  {}: {} (NetID: {}, ADS TCP {}, state {state})",
            dev.ip,
            dev.name,
            dev.netid_str,
            effective_ads_port(port)
        );
    }
    Ok(vec![dev])
}

/// Query the TwinCAT state via ADS. Pass `port = 0` to use the default ADS port (48898).
pub fn get_state(device: &BeckhoffDevice, local_netid: &str, port: u16) -> String {
    let effective_port = effective_ads_port(port);
    let mut stream = match TcpStream::connect_timeout(
        &format!("{}:{effective_port}", device.ip).parse().unwrap(),
        Duration::from_secs(3),
    ) {
        Ok(s) => s,
        Err(_) => return "ERROR".to_string(),
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));

    let packet = construct_ams_packet(
        &device.netid,
        local_netid,
        4,
        &AdsParams::ReadState,
        None,
        true,
        10000,
        31337,
    );

    let pkt = hex_decode(&packet);
    let resp = match send_recv_ams(&mut stream, &pkt) {
        Some(r) => r,
        None => return "ERROR".to_string(),
    };

    // AMS ReadState response: ads_data = result(4B) + ads_state(2B LE) + device_state(2B)
    // ads_state hex chars are at positions [8..12] in ads_data hex string
    let ams = match parse_ams_response(&resp) {
        Some(r) => r,
        None => return "ERROR".to_string(),
    };
    if ams.ads_data.len() < 12 {
        return "ERROR".to_string();
    }
    let state_lo = u8::from_str_radix(&ams.ads_data[8..10], 16).unwrap_or(0);
    let state_hi = u8::from_str_radix(&ams.ads_data[10..12], 16).unwrap_or(0);
    let ads_state = u16::from(state_lo) | (u16::from(state_hi) << 8);
    match ads_state {
        5 => "RUN".to_string(),
        6 => "STOP".to_string(),
        16 => "CONFIG".to_string(),
        _ => format!("STATE_{ads_state}"),
    }
}

/// Add a route on a remote Beckhoff device.
pub fn add_route(
    device: &BeckhoffDevice,
    local_ip: &str,
    local_netid: &str,
    username: &str,
    password: &str,
    route_name: Option<&str>,
) -> bool {
    let route_name = route_name
        .map(str::to_string)
        .unwrap_or_else(|| hostname_or_default());

    let sock = match UdpSocket::bind(format!("{local_ip}:0")) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));

    let name_len = format!("{:02x}", route_name.len() + 1);
    let name_hex = hex_str(route_name.as_bytes());
    let user_len = format!("{:02x}", username.len() + 1);
    let user_hex = hex_str(username.as_bytes());
    let pass_len = format!("{:02x}", password.len() + 1);
    let pass_hex = hex_str(password.as_bytes());
    let host_len = format!("{:02x}", local_ip.len() + 1);
    let host_hex = hex_str(local_ip.as_bytes());

    let packet = format!(
        "036614710000000006000000{local_netid}1027050000000c00{name_len}00{name_hex}00 07000600{local_netid}0d00{user_len}00{user_hex}00 0200{pass_len}00{pass_hex}00 0500{host_len}00{host_hex}00"
    );

    let pkt = hex_decode(&packet.replace(' ', ""));
    if sock
        .send_to(&pkt, format!("{}:{DISCOVERY_PORT}", device.ip))
        .is_err()
    {
        return false;
    }

    let mut buf = [0u8; 1024];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => {
            let resp = &buf[..n];
            resp.len() >= 4 && resp[resp.len() - 4..] == [0, 0, 0, 0]
        }
        Err(_) => false,
    }
}

/// Change the TwinCAT service state. Pass `port = 0` to use the default ADS port (48898).
pub fn set_twincat_state(
    device: &BeckhoffDevice,
    local_netid: &str,
    mode: &str,
    port: u16,
) -> Result<bool> {
    let ads_state: u16 = match mode.to_lowercase().as_str() {
        "run" => 5,     // ADS_STATE_RUN
        "reset" => 2,   // ADS_STATE_RESET
        "stop" => 6,    // ADS_STATE_STOP
        "config" => 16, // ADS_STATE_CONFIG
        _ => anyhow::bail!("Invalid mode '{mode}'. Use: run, stop, config, reset"),
    };
    let effective_port = effective_ads_port(port);
    let mut stream = TcpStream::connect_timeout(
        &format!("{}:{effective_port}", device.ip).parse()?,
        Duration::from_secs(5),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let packet = construct_ams_packet(
        &device.netid,
        local_netid,
        5,
        &AdsParams::WriteControl(ads_state, 0, vec![]),
        None,
        true,
        10000,
        31337,
    );

    let pkt = hex_decode(&packet);
    stream.write_all(&pkt)?;

    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;

    let ams = parse_ams_response(&buf[..n]);
    match ams {
        Some(r) if r.error_code == "00000000" => {
            println!("TwinCAT state changed to {}", mode.to_uppercase());
            Ok(true)
        }
        Some(r) => {
            println!("State change failed (error: {})", r.error_code);
            Ok(false)
        }
        None => Ok(false),
    }
}

/// Get detailed device info (ADS read XML for TC3 devices). Pass `port = 0` for default (48898).
pub fn get_device_info_full(
    device: &BeckhoffDevice,
    local_netid: &str,
    port: u16,
) -> Option<BeckhoffDeviceInfo> {
    let effective_port = effective_ads_port(port);
    let mut stream = TcpStream::connect_timeout(
        &format!("{}:{effective_port}", device.ip).parse().ok()?,
        Duration::from_secs(5),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;

    let mut info = BeckhoffDeviceInfo {
        ip: device.ip.clone(),
        name: device.name.clone(),
        netid: device.netid_str.clone(),
        tc_version: device.tc_version.clone(),
        kernel: device.kernel.clone(),
        target_type: None,
        target_version: None,
        hardware_model: None,
        serial: None,
        os_name: None,
        os_version: None,
    };

    if device.tc_version.starts_with('3') {
        // ADS Read to get XML info
        let pkt1 = construct_ams_packet(
            &device.netid,
            local_netid,
            2,
            &AdsParams::Read(700, 1, 4),
            None,
            true,
            10000,
            31337,
        );
        let _ = send_recv_ams(&mut stream, &hex_decode(&pkt1)).and_then(|resp| {
            let ams = parse_ams_response(&resp)?;
            let (_, ads_data) = parse_ads_response(&ams.ads_data)?;
            let resp_len = u32::from_str_radix(&reverse_bytes(&ads_data), 16).ok()? as u32;

            let pkt2 = construct_ams_packet(
                &device.netid,
                local_netid,
                2,
                &AdsParams::Read(700, 1, resp_len),
                None,
                true,
                10000,
                31337,
            );
            let resp2 = send_recv_ams(&mut stream, &hex_decode(&pkt2))?;
            let ams2 = parse_ams_response(&resp2)?;
            let (_, xml_hex) = parse_ads_response(&ams2.ads_data)?;
            let xml_bytes: Vec<u8> = hex_decode(&xml_hex)
                .into_iter()
                .filter(|&b| b != 0)
                .collect();
            let xml_str = String::from_utf8_lossy(&xml_bytes).to_string();
            parse_tc3_xml(&xml_str, &mut info);
            Some(())
        });
    }

    Some(info)
}

fn parse_tc3_xml(xml: &str, info: &mut BeckhoffDeviceInfo) {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut current_path = Vec::<String>::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                current_path.push(String::from_utf8_lossy(e.name().as_ref()).to_string());
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                let path = current_path.join("/");
                match path.as_str() {
                    p if p.contains("TargetType") => info.target_type = Some(text),
                    p if p.contains("HardwareModel") || p.contains("strType") => {
                        info.hardware_model = Some(text)
                    }
                    p if p.contains("SerialNo") => info.serial = Some(text),
                    p if p.contains("ImageOsName") => info.os_name = Some(text),
                    p if p.contains("ImageVersion") => info.os_version = Some(text),
                    _ => {}
                }
            }
            Ok(Event::End(_)) => {
                current_path.pop();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
}

#[derive(Debug, Clone)]
pub struct BeckhoffDeviceInfo {
    pub ip: String,
    pub name: String,
    pub netid: String,
    pub tc_version: String,
    pub kernel: String,
    pub target_type: Option<String>,
    pub target_version: Option<String>,
    pub hardware_model: Option<String>,
    pub serial: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
}

// ADS symbol index groups (Beckhoff standard).
const ADSIGRP_SYM_UPLOADINFO: u32 = 0xF00F;
const ADSIGRP_SYM_UPLOAD: u32 = 0xF00B;
const MAX_VALUE_READS: usize = 500;

#[derive(Debug, Clone)]
pub struct AdsSymbol {
    pub name: String,
    pub type_name: String,
    pub index_group: u32,
    pub index_offset: u32,
    pub size: u32,
    pub value_str: Option<String>,
}

/// Enumerate ADS symbols exposed by a Beckhoff device via the symbol upload
/// protocol, reading scalar values where possible. Returns an empty Vec if the
/// device does not support symbol upload or on any communication error.
/// Pass `port = 0` to use the default ADS port (48898).
pub fn enumerate_symbols(device: &BeckhoffDevice, local_netid: &str, port: u16) -> Vec<AdsSymbol> {
    let effective_port = effective_ads_port(port);
    let addr = match format!("{}:{effective_port}", device.ip).parse() {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .is_err()
    {
        return Vec::new();
    }

    let upload_size = match read_upload_info(&mut stream, device, local_netid) {
        Some(size) if size > 0 => size,
        _ => return Vec::new(),
    };

    let blob = match read_symbol_blob(&mut stream, device, local_netid, upload_size) {
        Some(b) => b,
        None => return Vec::new(),
    };

    let mut symbols = parse_symbol_entries(&blob);
    read_symbol_values(&mut stream, device, local_netid, &mut symbols);
    symbols
}

fn read_upload_info(
    stream: &mut TcpStream,
    device: &BeckhoffDevice,
    local_netid: &str,
) -> Option<u32> {
    let pkt = construct_ams_packet(
        &device.netid,
        local_netid,
        2,
        &AdsParams::Read(ADSIGRP_SYM_UPLOADINFO, 0, 8),
        None,
        true,
        10000,
        31337,
    );
    let resp = send_recv_ams(stream, &hex_decode(&pkt))?;
    let ams = parse_ams_response(&resp)?;
    let (error_code, data_hex) = parse_ads_response(&ams.ads_data)?;
    if error_code != "00000000" {
        return None;
    }
    let data = hex_decode(&data_hex);
    if data.len() < 8 {
        return None;
    }
    // data[0..4] = symbol count, data[4..8] = upload size (both little-endian).
    Some(u32_le(&data, 4))
}

fn read_symbol_blob(
    stream: &mut TcpStream,
    device: &BeckhoffDevice,
    local_netid: &str,
    upload_size: u32,
) -> Option<Vec<u8>> {
    let pkt = construct_ams_packet(
        &device.netid,
        local_netid,
        2,
        &AdsParams::Read(ADSIGRP_SYM_UPLOAD, 0, upload_size),
        None,
        true,
        10000,
        31337,
    );
    let resp = send_recv_ams(stream, &hex_decode(&pkt))?;
    let ams = parse_ams_response(&resp)?;
    let (error_code, blob_hex) = parse_ads_response(&ams.ads_data)?;
    if error_code != "00000000" {
        return None;
    }
    Some(hex_decode(&blob_hex))
}

fn parse_symbol_entries(blob: &[u8]) -> Vec<AdsSymbol> {
    let mut symbols = Vec::new();
    let mut pos = 0usize;

    while pos + 26 <= blob.len() {
        let entry_len = u32_le(blob, pos) as usize;
        if entry_len < 26 || pos + entry_len > blob.len() {
            break;
        }

        let index_group = u32_le(blob, pos + 4);
        let index_offset = u32_le(blob, pos + 8);
        let size = u32_le(blob, pos + 12);
        // pos+16: dataType (4 bytes), pos+20: flags (4 bytes)
        // pos+24: nameLen (2), pos+26: typeLen (2), pos+28: commentLen (2)
        let name_len = u16_le(blob, pos + 24) as usize;
        let type_len = u16_le(blob, pos + 26) as usize;
        // strings start at pos+30: name(nameLen)+NUL + type(typeLen)+NUL + ...
        let name_start = pos + 30;
        let name_end = name_start + name_len;
        let type_start = name_end + 1; // skip NUL terminator after name
        let type_end = type_start + type_len;
        if type_end > pos + entry_len {
            break;
        }

        let name = c_string(&blob[name_start..name_end]);
        let type_name = c_string(&blob[type_start..type_end]);

        symbols.push(AdsSymbol {
            name,
            type_name,
            index_group,
            index_offset,
            size,
            value_str: None,
        });

        pos += entry_len;
    }

    symbols
}

fn read_symbol_values(
    stream: &mut TcpStream,
    device: &BeckhoffDevice,
    local_netid: &str,
    symbols: &mut [AdsSymbol],
) {
    let mut reads = 0usize;
    for sym in symbols.iter_mut() {
        if reads >= MAX_VALUE_READS {
            break;
        }
        if sym.size == 0 || sym.size > 8 || !is_scalar_type(&sym.type_name) {
            continue;
        }
        reads += 1;

        let pkt = construct_ams_packet(
            &device.netid,
            local_netid,
            2,
            &AdsParams::Read(sym.index_group, sym.index_offset, sym.size),
            None,
            true,
            10000,
            31337,
        );
        let Some(resp) = send_recv_ams(stream, &hex_decode(&pkt)) else {
            continue;
        };
        let Some(ams) = parse_ams_response(&resp) else {
            continue;
        };
        let Some((error_code, data_hex)) = parse_ads_response(&ams.ads_data) else {
            continue;
        };
        if error_code != "00000000" {
            continue;
        }
        let bytes = hex_decode(&data_hex);
        sym.value_str = Some(decode_ads_value(&sym.type_name, &bytes));
    }
}

fn is_scalar_type(type_name: &str) -> bool {
    let t = type_name.trim().to_uppercase();
    matches!(
        t.as_str(),
        "BOOL"
            | "BYTE"
            | "USINT"
            | "SINT"
            | "WORD"
            | "UINT"
            | "INT"
            | "DWORD"
            | "UDINT"
            | "DINT"
            | "LWORD"
            | "ULINT"
            | "LINT"
            | "REAL"
            | "LREAL"
    ) || t.starts_with("STRING")
}

/// Send a request and read back a full AMS/TCP response, honoring the length
/// prefix so responses larger than a single TCP segment are fully collected.
fn send_recv_ams(stream: &mut TcpStream, data: &[u8]) -> Option<Vec<u8>> {
    stream.write_all(data).ok()?;
    let mut header = [0u8; 6];
    stream.read_exact(&mut header).ok()?;
    let len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
    let mut rest = vec![0u8; len];
    stream.read_exact(&mut rest).ok()?;
    let mut full = Vec::with_capacity(6 + len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&rest);
    Some(full)
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    if offset + 4 > bytes.len() {
        return 0;
    }
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u16_le(bytes: &[u8], offset: usize) -> u16 {
    if offset + 2 > bytes.len() {
        return 0;
    }
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write raw bytes to a symbol looked up by name from the device's symbol table.
/// Pass `port = 0` to use the default ADS port (48898).
pub fn write_symbol_value(
    device: &BeckhoffDevice,
    local_netid: &str,
    symbol_name: &str,
    value_bytes: Vec<u8>,
    port: u16,
) -> Result<bool> {
    let effective_port = effective_ads_port(port);
    let addr = format!("{}:{effective_port}", device.ip).parse()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let upload_size = read_upload_info(&mut stream, device, local_netid)
        .ok_or_else(|| anyhow::anyhow!("ADS: failed to read symbol upload info"))?;
    let blob = read_symbol_blob(&mut stream, device, local_netid, upload_size)
        .ok_or_else(|| anyhow::anyhow!("ADS: failed to read symbol blob"))?;
    let symbols = parse_symbol_entries(&blob);

    let sym = symbols
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(symbol_name))
        .ok_or_else(|| anyhow::anyhow!("ADS symbol '{symbol_name}' not found on device"))?;

    write_to_stream(
        &mut stream,
        device,
        local_netid,
        sym.index_group,
        sym.index_offset,
        value_bytes,
    )
}

/// Write raw bytes to a symbol identified by its ADS index group and offset.
/// Pass `port = 0` to use the default ADS port (48898).
pub fn write_symbol_by_index(
    device: &BeckhoffDevice,
    local_netid: &str,
    index_group: u32,
    index_offset: u32,
    data: Vec<u8>,
    port: u16,
) -> Result<bool> {
    let effective_port = effective_ads_port(port);
    let addr = format!("{}:{effective_port}", device.ip).parse()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write_to_stream(
        &mut stream,
        device,
        local_netid,
        index_group,
        index_offset,
        data,
    )
}

fn write_to_stream(
    stream: &mut TcpStream,
    device: &BeckhoffDevice,
    local_netid: &str,
    index_group: u32,
    index_offset: u32,
    data: Vec<u8>,
) -> Result<bool> {
    let pkt = construct_ams_packet(
        &device.netid,
        local_netid,
        3,
        &AdsParams::Write(index_group, index_offset, data),
        None,
        true,
        10000,
        31337,
    );
    let resp = send_recv_ams(stream, &hex_decode(&pkt))
        .ok_or_else(|| anyhow::anyhow!("ADS write: no response from device"))?;
    let ams = parse_ams_response(&resp)
        .ok_or_else(|| anyhow::anyhow!("ADS write: failed to parse AMS response"))?;
    let (error_code, _) = parse_ads_response(&ams.ads_data)
        .ok_or_else(|| anyhow::anyhow!("ADS write: failed to parse ADS response"))?;
    Ok(error_code == "00000000")
}

fn hostname_or_default() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "scadaver-rs".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_discovery_frame() -> Vec<u8> {
        let name = b"SCADAVER-CX";
        let name_len = name.len() + 1;
        let mut frame = vec![0u8; 340];
        frame[12..18].copy_from_slice(&[127, 0, 0, 1, 1, 1]);
        frame[26..28].copy_from_slice(&(name_len as u16).to_le_bytes());
        frame[28..28 + name.len()].copy_from_slice(name);

        let kernel_offset = 27 + name_len + 9;
        frame[kernel_offset..kernel_offset + 4].copy_from_slice(&3u32.to_le_bytes());
        frame[kernel_offset + 4..kernel_offset + 8].copy_from_slice(&1u32.to_le_bytes());
        frame[kernel_offset + 8..kernel_offset + 12].copy_from_slice(&4024u32.to_le_bytes());

        let tc_offset = kernel_offset + 12 + 264;
        frame[tc_offset] = 3;
        frame[tc_offset + 1] = 1;
        frame[tc_offset + 2..tc_offset + 4].copy_from_slice(&4024u16.to_le_bytes());
        frame
    }

    fn symbol_entry(
        name: &str,
        type_name: &str,
        index_group: u32,
        index_offset: u32,
        size: u32,
    ) -> Vec<u8> {
        let name_b = name.as_bytes();
        let type_b = type_name.as_bytes();
        let entry_len = 30 + name_b.len() + 1 + type_b.len() + 1;
        let mut entry = vec![0u8; entry_len];
        entry[0..4].copy_from_slice(&(entry_len as u32).to_le_bytes());
        entry[4..8].copy_from_slice(&index_group.to_le_bytes());
        entry[8..12].copy_from_slice(&index_offset.to_le_bytes());
        entry[12..16].copy_from_slice(&size.to_le_bytes());
        entry[24..26].copy_from_slice(&(name_b.len() as u16).to_le_bytes());
        entry[26..28].copy_from_slice(&(type_b.len() as u16).to_le_bytes());
        let type_start = 30 + name_b.len() + 1;
        entry[30..30 + name_b.len()].copy_from_slice(name_b);
        entry[type_start..type_start + type_b.len()].copy_from_slice(type_b);
        entry
    }

    #[test]
    fn discovery_frame_parser_extracts_core_metadata() {
        let dev = parse_discovery_frame(&sample_discovery_frame(), "127.0.0.1").unwrap();
        assert_eq!(dev.ip, "127.0.0.1");
        assert_eq!(dev.name, "SCADAVER-CX");
        assert_eq!(dev.netid_str, "127.0.0.1.1.1");
        assert_eq!(dev.kernel, "3.1.4024");
        assert_eq!(dev.tc_version, "3.1.4024");
    }

    #[test]
    fn symbol_blob_parser_extracts_symbol_entries() {
        let mut blob = symbol_entry("MAIN.counter", "UINT", 0x4020, 0, 2);
        blob.extend(symbol_entry("MAIN.running", "BOOL", 0x4020, 2, 1));

        let symbols = parse_symbol_entries(&blob);
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "MAIN.counter");
        assert_eq!(symbols[0].type_name, "UINT");
        assert_eq!(symbols[0].index_group, 0x4020);
        assert_eq!(symbols[0].index_offset, 0);
        assert_eq!(symbols[0].size, 2);
        assert_eq!(symbols[1].name, "MAIN.running");
        assert_eq!(symbols[1].type_name, "BOOL");
    }

    #[test]
    fn derived_ads_device_uses_ipv4_netid_fallback() {
        let dev = derived_ads_device("192.168.1.20", 49001).unwrap();
        assert_eq!(dev.ip, "192.168.1.20");
        assert_eq!(dev.netid, "c0a801140101");
        assert_eq!(dev.netid_str, "192.168.1.20.1.1");
        assert!(dev.name.contains("49001"));
        assert!(derived_ads_device("not-an-ip", 49001).is_none());
    }
}
