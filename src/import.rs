use quick_xml::{events::Event, Reader};

/// A host extracted from an nmap XML scan output.
pub struct NmapHost {
    pub ip: String,
    pub hostnames: Vec<String>,
    pub open_ports: Vec<u16>,
}

/// Parse an nmap XML file and return all hosts that are up and have at least one open port.
pub fn parse_nmap_xml(path: &str) -> anyhow::Result<Vec<NmapHost>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;

    let mut reader = Reader::from_str(&text);
    reader.config_mut().trim_text(true);

    let mut hosts: Vec<NmapHost> = Vec::new();
    let mut current: Option<NmapHost> = None;
    let mut in_hostname_element = false;
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
                        });
                    }
                    b"status" => {
                        if let Some(ref mut host) = current {
                            let state = attr_val(e, b"state").unwrap_or_default();
                            if state != "up" {
                                // Mark as down by clearing the IP sentinel so we skip it.
                                host.ip = "\x00down".to_string();
                            }
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
                            in_hostname_element = true;
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
                            current_port = attr_val(e, b"portid")
                                .and_then(|s| s.parse::<u16>().ok());
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
            Ok(Event::End(ref e)) => {
                match e.name().as_ref() {
                    b"hostname" => { in_hostname_element = false; }
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
                            if !host.ip.is_empty()
                                && !host.ip.starts_with('\x00')
                                && !host.open_ports.is_empty()
                            {
                                hosts.push(host);
                            }
                        }
                        in_hostname_element = false;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML parse error: {e}")),
            _ => {}
        }
    }

    let _ = in_hostname_element;
    Ok(hosts)
}

fn attr_val(e: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Option<String> {
    e.attributes()
        .filter_map(std::result::Result::ok)
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| String::from_utf8(a.value.into_owned()).ok())
}
