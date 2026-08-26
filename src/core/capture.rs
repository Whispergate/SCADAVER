use anyhow::Result;
use pcap_parser::{create_reader, PcapBlockOwned, PcapError};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

/// A single ICS device observed in packet traffic.
#[derive(Debug, Clone)]
pub struct DeviceObservation {
    pub ip: String,
    pub port: u16,
    pub protocol: &'static str,
    pub packet_count: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

// pcap link types we handle
const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_LINUX_SLL: u32 = 113;

// (src_ip, src_port, dst_ip, dst_port, is_tcp, payload)
type ParsedPacket<'a> = (String, u16, String, u16, bool, &'a [u8]);

fn parse_ethernet(data: &[u8]) -> Option<ParsedPacket<'_>> {
    if data.len() < 14 {
        return None;
    }
    let ether_type = u16::from_be_bytes([data[12], data[13]]);
    if ether_type != 0x0800 {
        return None; // Not IPv4
    }
    parse_ipv4(&data[14..])
}

fn parse_linux_sll(data: &[u8]) -> Option<ParsedPacket<'_>> {
    if data.len() < 16 {
        return None;
    }
    let ether_type = u16::from_be_bytes([data[14], data[15]]);
    if ether_type != 0x0800 {
        return None;
    }
    parse_ipv4(&data[16..])
}

fn parse_ipv4(ip: &[u8]) -> Option<ParsedPacket<'_>> {
    if ip.len() < 20 || (ip[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let protocol = ip[9];
    let src_ip = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    let transport = &ip[ihl..];
    if transport.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([transport[0], transport[1]]);
    let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
    match protocol {
        6 => {
            // TCP minimum header is 20 bytes; data-offset lives at byte 12.
            if transport.len() < 20 {
                return None;
            }
            let data_offset = ((transport[12] >> 4) as usize) * 4;
            if transport.len() < data_offset {
                return None;
            }
            Some((src_ip, src_port, dst_ip, dst_port, true, &transport[data_offset..]))
        }
        17 => Some((src_ip, src_port, dst_ip, dst_port, false, &transport[8..])),
        _ => None,
    }
}

fn detect_protocol(port: u16, is_tcp: bool, payload: &[u8]) -> Option<&'static str> {
    match (port, is_tcp) {
        (502, _) => {
            // Modbus MBAP: protocol ID at bytes 2-3 must be 0x0000
            let ok = payload.is_empty()
                || (payload.len() >= 4 && payload[2] == 0x00 && payload[3] == 0x00);
            if ok { Some("Modbus") } else { None }
        }
        (44818, _) => {
            // EtherNet/IP: first byte is an EIP command code
            let ok = payload.is_empty()
                || matches!(payload[0], 0x00 | 0x01 | 0x04 | 0x05 | 0x63 | 0x64 | 0x65);
            if ok { Some("EtherNet/IP") } else { None }
        }
        (47808, false) => {
            // BACnet/IP UDP: BVLC type byte is 0x81
            if payload.first() == Some(&0x81) { Some("BACnet/IP") } else { None }
        }
        (102, true) => {
            // S7Comm over ISO-TSAP: TPKT starts with version byte 0x03
            if payload.first() == Some(&0x03) { Some("S7Comm") } else { None }
        }
        (20000, _) => {
            // DNP3: start bytes are 0x05 0x64
            let ok =
                payload.len() >= 2 && payload[0] == 0x05 && payload[1] == 0x64;
            if ok { Some("DNP3") } else { None }
        }
        (2404, true) => {
            // IEC 60870-5-104: APCI start byte is 0x68
            if payload.first() == Some(&0x68) { Some("IEC104") } else { None }
        }
        (1883 | 8883, true) => {
            // MQTT: high nibble of first byte is the packet type (1–14)
            let ok = payload.is_empty()
                || payload.first().is_some_and(|&b| (b >> 4) >= 1 && (b >> 4) <= 14);
            if ok { Some("MQTT") } else { None }
        }
        (161 | 162, false) => {
            // SNMP UDP: ASN.1 SEQUENCE tag is 0x30
            if payload.first() == Some(&0x30) { Some("SNMP") } else { None }
        }
        (4840, true) => {
            // OPC-UA Binary: 3-byte message type ("HEL", "MSG", "OPN", …) + chunk type 'F'
            let ok = payload.is_empty()
                || (payload.len() >= 4
                    && matches!(
                        &payload[0..3],
                        b"HEL" | b"ACK" | b"ERR" | b"MSG" | b"OPN" | b"CLO" | b"RHE"
                    )
                    && payload[3] == b'F');
            if ok { Some("OPC-UA") } else { None }
        }
        _ => None,
    }
}

/// Update the observation map for one raw packet.
#[allow(clippy::implicit_hasher)]
pub fn classify_packet(
    data: &[u8],
    link_type: u32,
    obs: &mut HashMap<(String, u16), DeviceObservation>,
    ts_epoch: u64,
) {
    let parsed = match link_type {
        LINKTYPE_ETHERNET => parse_ethernet(data),
        LINKTYPE_RAW => parse_ipv4(data),
        LINKTYPE_LINUX_SLL => parse_linux_sll(data),
        _ => None,
    };
    let Some((src_ip, src_port, dst_ip, dst_port, is_tcp, payload)) = parsed else {
        return;
    };

    // The ICS device is whichever side uses the well-known port.
    // Prefer dst (responder/server) over src (initiator).
    let (device_ip, device_port, proto) =
        if let Some(p) = detect_protocol(dst_port, is_tcp, payload) {
            (dst_ip, dst_port, p)
        } else if let Some(p) = detect_protocol(src_port, is_tcp, payload) {
            (src_ip, src_port, p)
        } else {
            return;
        };

    let key = (device_ip.clone(), device_port);
    let entry = obs.entry(key).or_insert(DeviceObservation {
        ip: device_ip,
        port: device_port,
        protocol: proto,
        packet_count: 0,
        first_seen: ts_epoch,
        last_seen: ts_epoch,
    });
    entry.packet_count += 1;
    entry.last_seen = ts_epoch;
}

/// Ingest a `.pcap` or `.pcapng` file and return observed ICS devices,
/// sorted by packet count descending.
pub fn ingest_file(path: &str) -> Result<Vec<DeviceObservation>> {
    let file = File::open(path)?;
    let mut reader = create_reader(65_536, BufReader::new(file))
        .map_err(|e| anyhow::anyhow!("failed to open pcap: {e:?}"))?;

    let mut obs: HashMap<(String, u16), DeviceObservation> = HashMap::new();
    let mut link_type: u32 = LINKTYPE_ETHERNET;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        link_type = hdr.network.0.cast_unsigned();
                    }
                    PcapBlockOwned::Legacy(pkt) => {
                        classify_packet(pkt.data, link_type, &mut obs, u64::from(pkt.ts_sec));
                    }
                    PcapBlockOwned::NG(ng_block) => {
                        use pcap_parser::Block;
                        match ng_block {
                            Block::InterfaceDescription(idb) => {
                                link_type = idb.linktype.0.cast_unsigned();
                            }
                            Block::EnhancedPacket(epb) => {
                                let ts_us =
                                    (u64::from(epb.ts_high) << 32) | u64::from(epb.ts_low);
                                classify_packet(
                                    epb.data,
                                    link_type,
                                    &mut obs,
                                    ts_us / 1_000_000,
                                );
                            }
                            Block::SimplePacket(spb) => {
                                classify_packet(spb.data, link_type, &mut obs, 0);
                            }
                            _ => {}
                        }
                    }
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| anyhow::anyhow!("pcap read error: {e:?}"))?;
            }
            Err(e) => return Err(anyhow::anyhow!("pcap error: {e:?}")),
        }
    }

    let mut result: Vec<DeviceObservation> = obs.into_values().collect();
    result.sort_by_key(|d| std::cmp::Reverse(d.packet_count));
    Ok(result)
}

/// Print a table of observed ICS devices.
pub fn print_table(obs: &[DeviceObservation]) {
    if obs.is_empty() {
        println!("No ICS devices detected in capture.");
        return;
    }
    println!(
        "{:<18} {:<7} {:<14} {:>8}  First Seen",
        "IP Address", "Port", "Protocol", "Packets"
    );
    println!("{}", "-".repeat(70));
    for d in obs {
        let ts = if d.first_seen == 0 {
            "unknown".to_string()
        } else {
            format!("T+{}s", d.first_seen)
        };
        println!(
            "{:<18} {:<7} {:<14} {:>8}  {}",
            d.ip, d.port, d.protocol, d.packet_count, ts
        );
    }
}

/// Live capture on `iface` (or the default device when `None`).
/// Stops after `max_packets` frames (0 = until Ctrl-C).
/// Optionally saves packets to `output` as a `.pcap` file.
#[cfg(feature = "capture")]
pub fn live_capture(iface: Option<&str>, output: Option<&str>, max_packets: u64) -> Result<()> {
    use pcap::{Capture, Device};
    let device = if let Some(name) = iface {
        Device::list()
            .map_err(|e| anyhow::anyhow!("cannot list interfaces: {e}"))?
            .into_iter()
            .find(|d| d.name == name)
            .ok_or_else(|| anyhow::anyhow!("interface not found: {name}"))?
    } else {
        Device::lookup()
            .map_err(|e| anyhow::anyhow!("interface lookup failed: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("no default capture interface found"))?
    };

    let iface_name = device.name.clone();
    println!("Capturing on {iface_name} (Ctrl-C to stop)…");

    let mut cap = Capture::from_device(device)
        .map_err(|e| anyhow::anyhow!("open device: {e}"))?
        .promisc(true)
        .snaplen(65_535)
        .open()
        .map_err(|e| anyhow::anyhow!("activate capture: {e}"))?;

    let link_type = cap.get_datalink().0.cast_unsigned();

    let mut savefile = if let Some(path) = output {
        Some(cap.savefile(path).map_err(|e| anyhow::anyhow!("open savefile: {e}"))?)
    } else {
        None
    };

    let mut obs: HashMap<(String, u16), DeviceObservation> = HashMap::new();
    let mut count: u64 = 0;

    loop {
        if max_packets > 0 && count >= max_packets {
            break;
        }
        match cap.next_packet() {
            Ok(pkt) => {
                #[allow(clippy::cast_sign_loss)]
                let ts = pkt.header.ts.tv_sec as u64;
                classify_packet(pkt.data, link_type, &mut obs, ts);
                if let Some(sf) = savefile.as_mut() {
                    sf.write(&pkt);
                }
                count += 1;
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("capture error: {e}");
                break;
            }
        }
    }

    let mut result: Vec<DeviceObservation> = obs.into_values().collect();
    result.sort_by_key(|d| std::cmp::Reverse(d.packet_count));
    print_table(&result);
    if let Some(path) = output {
        println!("Saved {count} packets to {path}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_eth_ipv4_tcp(
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        // Ethernet (14) + IPv4 (20) + TCP (20 min) + payload
        let total_ip = 20 + 20 + payload.len();
        let mut pkt = vec![0u8; 14 + total_ip];
        // Ethernet: EtherType = 0x0800
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        // IPv4 header
        pkt[14] = 0x45; // version=4, IHL=5
        let len = total_ip as u16;
        pkt[16] = (len >> 8) as u8;
        pkt[17] = len as u8;
        pkt[23] = 6; // TCP
        pkt[26..30].copy_from_slice(&src_ip);
        pkt[30..34].copy_from_slice(&dst_ip);
        // TCP header
        pkt[34..36].copy_from_slice(&src_port.to_be_bytes());
        pkt[36..38].copy_from_slice(&dst_port.to_be_bytes());
        pkt[46] = 0x50; // data offset = 5 (20 bytes)
        // Payload
        pkt[54..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn modbus_packet_detected() {
        // Modbus MBAP: transaction(2) + protocol(2=0x00,0x00) + length(2) + unit(1) + pdu
        let mbap = &[0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01];
        let pkt = make_eth_ipv4_tcp([10, 0, 0, 5], 12345, [10, 0, 0, 1], 502, mbap);
        let mut obs = HashMap::new();
        classify_packet(&pkt, LINKTYPE_ETHERNET, &mut obs, 1000);
        assert!(obs.contains_key(&("10.0.0.1".to_string(), 502)), "Modbus not detected");
        let dev = &obs[&("10.0.0.1".to_string(), 502)];
        assert_eq!(dev.protocol, "Modbus");
        assert_eq!(dev.packet_count, 1);
    }

    #[test]
    fn non_ics_port_ignored() {
        let pkt = make_eth_ipv4_tcp([10, 0, 0, 5], 12345, [10, 0, 0, 1], 80, b"GET / HTTP/1.1");
        let mut obs = HashMap::new();
        classify_packet(&pkt, LINKTYPE_ETHERNET, &mut obs, 1000);
        assert!(obs.is_empty(), "HTTP port 80 should not be classified as ICS");
    }

    #[test]
    fn s7comm_packet_detected() {
        // S7Comm/TPKT starts with 0x03
        let pkt = make_eth_ipv4_tcp([10, 0, 0, 5], 9999, [192, 168, 1, 10], 102, &[0x03, 0x00]);
        let mut obs = HashMap::new();
        classify_packet(&pkt, LINKTYPE_ETHERNET, &mut obs, 2000);
        assert!(obs.contains_key(&("192.168.1.10".to_string(), 102)));
        assert_eq!(obs[&("192.168.1.10".to_string(), 102)].protocol, "S7Comm");
    }

    #[test]
    fn response_direction_maps_to_device() {
        // Packet coming FROM the device (src=502): should still map to 10.0.0.1:502
        let mbap = &[0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x02];
        let pkt = make_eth_ipv4_tcp([10, 0, 0, 1], 502, [10, 0, 0, 5], 12345, mbap);
        let mut obs = HashMap::new();
        classify_packet(&pkt, LINKTYPE_ETHERNET, &mut obs, 3000);
        assert!(obs.contains_key(&("10.0.0.1".to_string(), 502)));
    }

    #[test]
    fn truncated_tcp_header_does_not_panic() {
        // Regression: transport[12] (TCP data-offset) was accessed with only a `< 8` guard.
        // A TCP segment with 8–19 transport bytes passes that guard but has no byte 12.
        // Fix: added `< 20` guard in the TCP match arm.
        //
        // Build: Ethernet(14) + IPv4(20) + 10 bytes of TCP (truncated — no data-offset field)
        let mut pkt = vec![0u8; 14 + 20 + 10];
        pkt[12] = 0x08; pkt[13] = 0x00; // EtherType = IPv4
        pkt[14] = 0x45;                  // version=4, IHL=5 (20 bytes)
        pkt[23] = 6;                     // protocol = TCP
        pkt[26..30].copy_from_slice(&[10, 0, 0, 1]);   // src IP
        pkt[30..34].copy_from_slice(&[10, 0, 0, 2]);   // dst IP
        // TCP src port = 502 (Modbus) so it would be classified if parsing succeeded
        pkt[34..36].copy_from_slice(&[0x01, 0xf6]);
        pkt[36..38].copy_from_slice(&[0x00, 0x50]); // dst port 80

        let mut obs = HashMap::new();
        // Must not panic; truncated TCP header is silently discarded.
        classify_packet(&pkt, LINKTYPE_ETHERNET, &mut obs, 0);
        assert!(obs.is_empty(), "truncated TCP should produce no observation");
    }
}
