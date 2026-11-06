use quick_xml::{events::Event, Reader};

/// A host extracted from an nmap XML scan output.
pub struct NmapHost {
    pub ip: String,
    pub hostnames: Vec<String>,
    pub open_ports: Vec<u16>,
    pub is_up: bool,
}

/// Parse an nmap XML file and return all hosts that are up and have at least one open port.
pub fn parse_nmap_xml(path: &str) -> anyhow::Result<Vec<NmapHost>> {
    let text =
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;

    let mut reader = Reader::from_str(&text);
    reader.config_mut().trim_text(true);

    let mut hosts: Vec<NmapHost> = Vec::new();
    let mut current: Option<NmapHost> = None;
    let mut port_open = false;
    let mut current_port: Option<u16> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                match e.name().as_ref() {
                    b"host" => {
                        current = Some(NmapHost {
                            ip: String::new(),
                            hostnames: Vec::new(),
                            open_ports: Vec::new(),
                            is_up: true,
                        });
                    }
                    b"status" => {
                        if let Some(ref mut host) = current {
                            let state = attr_val(e, b"state").unwrap_or_default();
                            host.is_up = state == "up";
                        }
                    }
                    b"address" => {
                        if let Some(ref mut host) = current {
                            let addr_type = attr_val(e, b"addrtype").unwrap_or_default();
                            if addr_type == "ipv4" {
                                if let Some(addr) = attr_val(e, b"addr") {
                                    host.ip = addr;
                                }
                            }
                        }
                    }
                    b"hostname" => {
                        if let Some(ref mut host) = current {
                            if let Some(name) = attr_val(e, b"name") {
                                if !name.is_empty() {
                                    host.hostnames.push(name);
                                }
                            }
                        }
                    }
                    b"port" => {
                        if current.is_some() {
                            port_open = false;
                            current_port =
                                attr_val(e, b"portid").and_then(|s| s.parse::<u16>().ok());
                        }
                    }
                    b"state" => {
                        let state = attr_val(e, b"state").unwrap_or_default();
                        if state == "open" {
                            port_open = true;
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => match e.name().as_ref() {
                b"port" => {
                    if let (Some(ref mut host), Some(port), true) =
                        (current.as_mut(), current_port, port_open)
                    {
                        host.open_ports.push(port);
                    }
                    port_open = false;
                    current_port = None;
                }
                b"host" => {
                    if let Some(host) = current.take() {
                        if host.is_up && !host.ip.is_empty() && !host.open_ports.is_empty() {
                            hosts.push(host);
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML parse error: {e}")),
            _ => {}
        }
    }

    Ok(hosts)
}

fn attr_val(e: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Option<String> {
    e.attributes()
        .filter_map(std::result::Result::ok)
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| String::from_utf8(a.value.into_owned()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_xml_str(xml: &str) -> anyhow::Result<Vec<NmapHost>> {
        use std::io::Write;
        // Write to a uniquely-named temp file keyed by thread id to avoid collisions.
        let id = std::thread::current().id();
        let path = std::env::temp_dir().join(format!("scadaver_import_test_{id:?}.xml"));
        std::fs::File::create(&path)?.write_all(xml.as_bytes())?;
        let result = parse_nmap_xml(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        result
    }

    #[test]
    fn down_host_with_address_is_excluded() {
        // <status> comes before <address> in nmap XML; the old sentinel was overwritten
        // by the real IP, letting down hosts slip through. This test verifies the fix.
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="502">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;
        let hosts = parse_xml_str(xml).unwrap();
        assert!(
            hosts.is_empty(),
            "down host must be excluded even when <address> follows <status>"
        );
    }

    #[test]
    fn up_host_with_open_ports_is_included() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="102">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;
        let hosts = parse_xml_str(xml).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "192.168.1.5");
        assert_eq!(hosts[0].open_ports, vec![102]);
        assert!(hosts[0].is_up);
    }
}
