//! Interactive MQTT client shell for broker reconnaissance and testing.
//!
//! Based on python-mqtt-client-shell by Barry Powell
//! (<https://github.com/bapowell/python-mqtt-client-shell>)

use anyhow::Result;
use std::collections::HashMap;
use std::io::{self, Write};
use std::time::Duration;
use std::thread;

use scadaver::vendors::mqtt::session::{ConnectOptions, MqttMessage, MqttSession, WillConfig};

// ── Shell entry point ─────────────────────────────────────────────────────────

/// Launch the interactive MQTT shell, optionally pre-populating the broker host/port.
pub fn run_shell(host: Option<&str>, port: u16) -> Result<()> {
    println!();
    println!("  MQTT Client Shell");
    println!("  Based on python-mqtt-client-shell by Barry Powell");
    println!("  (https://github.com/bapowell/python-mqtt-client-shell)");
    println!();
    println!("  Type 'help' at any prompt.  'exit' exits the current level.");
    println!();

    let mut ms = MainState::default();
    let mut cs = ConnState::default();
    if let Some(h) = host {
        cs.host = h.to_string();
    }
    if port != 0 && port != 1883 {
        cs.port = port;
    }
    main_console(&mut ms, &mut cs)
}

// ── State structs ─────────────────────────────────────────────────────────────

struct MainState {
    client_id: String,
    clean_session: bool,
}

impl Default for MainState {
    fn default() -> Self {
        Self { client_id: "scadaver-shell".into(), clean_session: true }
    }
}

struct ConnState {
    host: String,
    port: u16,
    keepalive: u16,
    username: Option<String>,
    password: Option<String>,
    will: Option<WillConfig>,
}

impl Default for ConnState {
    fn default() -> Self {
        Self { host: "localhost".into(), port: 1883, keepalive: 60, username: None, password: None, will: None }
    }
}

impl ConnState {
    fn to_connect_options(&self, ms: &MainState) -> ConnectOptions {
        ConnectOptions {
            host: self.host.clone(),
            port: self.port,
            client_id: ms.client_id.clone(),
            keepalive: self.keepalive,
            clean_session: ms.clean_session,
            username: self.username.clone(),
            password: self.password.clone(),
            will: self.will.clone(),
        }
    }
}

// ── Console levels ────────────────────────────────────────────────────────────

fn main_console(ms: &mut MainState, cs: &mut ConnState) -> Result<()> {
    loop {
        let line = read_line("mqtt> ")?;
        let (cmd, args) = split_first(&line);
        match cmd {
            "client_id" if args.is_empty() => {
                println!("  client_id = {}", ms.client_id);
            }
            "client_id" => {
                ms.client_id = args.to_string();
                println!("  client_id set to '{}'", ms.client_id);
            }
            "clean_session" if args.is_empty() => {
                println!("  clean_session = {}", ms.clean_session);
            }
            "clean_session" => {
                ms.clean_session = !matches!(args.to_lowercase().as_str(), "false" | "0" | "no");
                println!("  clean_session = {}", ms.clean_session);
            }
            "connection" => {
                connection_console(ms, cs)?;
            }
            "status" => print_main_status(ms, cs),
            "help" | "?" => print_main_help(),
            "exit" | "quit" => break,
            "" => {}
            _ => println!("  unknown command '{cmd}'  (type 'help' for list)"),
        }
    }
    Ok(())
}

fn connection_console(ms: &mut MainState, cs: &mut ConnState) -> Result<()> {
    loop {
        let line = read_line("mqtt/connection> ")?;
        let (cmd, args) = split_first(&line);
        match cmd {
            "host" if args.is_empty() => println!("  host = {}", cs.host),
            "host" => { cs.host = args.to_string(); println!("  host = {}", cs.host); }
            "port" if args.is_empty() => println!("  port = {}", cs.port),
            "port" => match args.parse::<u16>() {
                Ok(p) => { cs.port = p; println!("  port = {p}"); }
                Err(_) => println!("  invalid port '{args}'"),
            },
            "keepalive" if args.is_empty() => println!("  keepalive = {}", cs.keepalive),
            "keepalive" => match args.parse::<u16>() {
                Ok(k) => { cs.keepalive = k; println!("  keepalive = {k}s"); }
                Err(_) => println!("  invalid keepalive '{args}'"),
            },
            "username" if args.is_empty() => {
                match &cs.username {
                    Some(u) => println!("  username = {u}"),
                    None => println!("  username = (not set)"),
                }
            }
            "username" => {
                cs.username = Some(args.to_string());
                println!("  username = {args}");
            }
            "clear_username" => {
                cs.username = None;
                println!("  username cleared");
            }
            "password" => {
                let pass = read_password("  Password: ")?;
                cs.password = Some(pass);
                println!("  password set");
            }
            "clear_password" => { cs.password = None; println!("  password cleared"); }
            "will" => handle_will_cmd(cs, args),
            "clear_will" => { cs.will = None; println!("  will cleared"); }
            "connect" => {
                if cs.host.is_empty() {
                    println!("  set a host first: host <hostname>");
                    continue;
                }
                let opts = cs.to_connect_options(ms);
                print!("  Connecting to {}:{}… ", opts.host, opts.port);
                let _ = io::stdout().flush();
                match MqttSession::connect(&opts) {
                    Ok(session) => {
                        println!("connected.");
                        println!();
                        messaging_console(cs, session)?;
                    }
                    Err(e) => println!("failed: {e:#}"),
                }
            }
            "status" => print_conn_status(ms, cs),
            "help" | "?" => print_conn_help(),
            "exit" | "quit" => break,
            "" => {}
            _ => println!("  unknown command '{cmd}'  (type 'help' for list)"),
        }
    }
    Ok(())
}

fn messaging_console(cs: &ConnState, mut session: MqttSession) -> Result<()> {
    let mut logging = true;
    let mut seq: u64 = 0;
    let mut filter = String::new();
    let mut topic_stats: HashMap<String, usize> = HashMap::new();
    println!("  Logging is ON.  Incoming messages will appear before each prompt.");
    println!("  Type 'help' for commands.");
    println!();

    loop {
        // Drain and optionally print queued messages before each prompt.
        for msg in session.drain_messages() {
            *topic_stats.entry(msg.topic.clone()).or_insert(0) += 1;
            if logging && matches_filter(&msg, &filter) {
                let payload = msg.payload_str();
                println!();
                println!("  [{}] {} : {}", if msg.retain { "R" } else { " " }, msg.topic, payload);
            }
        }

        let line = read_line("mqtt/messaging> ")?;
        let (cmd, rest) = split_first(&line);

        match cmd {
            "filter" => apply_filter_cmd(&mut filter, rest),
            "topics" => show_topics(&topic_stats),
            "subscribe" | "sub" => {
                let (topic, qos_str) = split_first(rest);
                if topic.is_empty() {
                    println!("  usage: subscribe <topic> [qos]");
                    continue;
                }
                let qos: u8 = qos_str.parse().unwrap_or(0).min(2);
                match session.subscribe(topic, qos) {
                    Ok(()) => println!("  subscribed to '{topic}' (QoS {qos})"),
                    Err(e) => println!("  subscribe failed: {e:#}"),
                }
            }
            "unsubscribe" | "unsub" => {
                if rest.is_empty() {
                    println!("  usage: unsubscribe <topic>");
                    continue;
                }
                match session.unsubscribe(rest) {
                    Ok(()) => println!("  unsubscribed from '{rest}'"),
                    Err(e) => println!("  unsubscribe failed: {e:#}"),
                }
            }
            "unsubscribe_all" | "unsub_all" => {
                match session.unsubscribe_all() {
                    Ok(()) => println!("  unsubscribed from all topics"),
                    Err(e) => println!("  error: {e:#}"),
                }
            }
            "list_subscriptions" | "subs" | "ls" => {
                let subs = session.subscriptions();
                if subs.is_empty() {
                    println!("  (no subscriptions)");
                } else {
                    for s in subs {
                        println!("  {s}");
                    }
                }
            }
            "publish" | "pub" => handle_publish_cmd(&mut session, rest, &mut seq),
            "listen" => handle_listen_cmd(&session, rest, &filter, &mut topic_stats),
            "logging" => {
                logging = match rest.to_lowercase().as_str() {
                    "off" | "0" | "false" => {
                        println!("  logging off"); false
                    }
                    "on" | "1" | "true" | "" => {
                        println!("  logging on"); true
                    }
                    _ => { println!("  usage: logging on|off"); logging }
                };
            }
            "ping" => match session.ping() {
                Ok(()) => println!("  PINGREQ sent"),
                Err(e) => println!("  ping failed: {e:#}"),
            },
            "disconnect" => {
                let _ = session.disconnect();
                println!("  disconnected from {}:{}", cs.host, cs.port);
                println!();
                return Ok(());
            }
            "help" | "?" => print_msg_help(),
            "exit" | "quit" => {
                let _ = session.disconnect();
                println!("  disconnected.");
                return Ok(());
            }
            "" => {}
            _ => println!("  unknown command '{cmd}'  (type 'help' for list)"),
        }
    }
}

// ── Command handlers ──────────────────────────────────────────────────────────

fn handle_will_cmd(cs: &mut ConnState, args: &str) {
    // will <topic> [<payload> [<qos> [<retain>]]]
    let parts: Vec<&str> = args.splitn(4, ' ').collect();
    let Some(&topic) = parts.first() else {
        println!("  usage: will <topic> [payload [qos [retain]]]");
        return;
    };
    if topic.is_empty() {
        println!("  usage: will <topic> [payload [qos [retain]]]");
        return;
    }
    let payload = parts.get(1).copied().unwrap_or("").as_bytes().to_vec();
    let qos: u8 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let retain: bool = matches!(parts.get(3).copied(), Some("true" | "1"));
    cs.will = Some(WillConfig { topic: topic.to_string(), payload, qos, retain });
    println!("  will set: topic='{topic}' qos={qos} retain={retain}");
}

fn handle_publish_cmd(session: &mut MqttSession, args: &str, seq: &mut u64) {
    // publish <topic> [<payload> [<qos> [<retain>]]]
    let parts: Vec<&str> = args.splitn(4, ' ').collect();
    let Some(&topic) = parts.first() else {
        println!("  usage: publish <topic> [payload [qos [retain]]]");
        return;
    };
    if topic.is_empty() {
        println!("  usage: publish <topic> [payload [qos [retain]]]");
        return;
    }
    let raw_payload = parts.get(1).copied().unwrap_or("");
    let payload_str = apply_seq(raw_payload, seq);
    let qos: u8 = parts.get(2).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0).min(2);
    let retain: bool = matches!(parts.get(3).copied(), Some("true" | "1"));

    match session.publish(topic, payload_str.as_bytes(), qos, retain) {
        Ok(()) => {
            println!(
                "  published → '{topic}' payload='{payload_str}' qos={qos} retain={retain}"
            );
        }
        Err(e) => println!("  publish failed: {e:#}"),
    }
}

fn handle_listen_cmd(
    session: &MqttSession,
    args: &str,
    filter: &str,
    topic_stats: &mut HashMap<String, usize>,
) {
    let secs: u64 = args.parse().unwrap_or(5);
    let filter_note = if filter.is_empty() { String::new() } else { format!(" [filter: {filter}]") };
    println!("  Listening for {secs}s{filter_note}…");
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    let mut shown = 0usize;
    let mut total = 0usize;
    while std::time::Instant::now() < deadline {
        for msg in session.drain_messages() {
            total += 1;
            *topic_stats.entry(msg.topic.clone()).or_insert(0) += 1;
            if matches_filter(&msg, filter) {
                println!("  [{}] {} : {}", if msg.retain { "R" } else { " " }, msg.topic, msg.payload_str());
                shown += 1;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    if filter.is_empty() {
        println!("  listened {secs}s — {total} message(s), {} unique topic(s).", topic_stats.len());
    } else {
        println!("  listened {secs}s — {shown} shown, {total} received, {} unique topic(s).", topic_stats.len());
    }
}

fn apply_filter_cmd(filter: &mut String, pattern: &str) {
    if pattern.is_empty() {
        filter.clear();
        println!("  filter cleared — all messages shown");
    } else {
        pattern.clone_into(filter);
        println!("  filter set to '{filter}' (topic or payload substring, case-insensitive)");
    }
}

fn show_topics(topic_stats: &HashMap<String, usize>) {
    if topic_stats.is_empty() {
        println!("  (no messages received yet)");
        return;
    }
    let mut rows: Vec<(&String, &usize)> = topic_stats.iter().collect();
    rows.sort_by_key(|(t, _)| t.as_str());
    println!("  {:<48} msgs", "topic");
    println!("  {}", "─".repeat(56));
    for (topic, count) in &rows {
        println!("  {topic:<48} {count}");
    }
    println!(
        "  {} unique topic(s), {} message(s) total",
        rows.len(),
        rows.iter().map(|(_, &c)| c).sum::<usize>()
    );
}

fn matches_filter(msg: &MqttMessage, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    let f = filter.to_lowercase();
    msg.topic.to_lowercase().contains(&f) || msg.payload_str().to_lowercase().contains(&f)
}

fn apply_seq(payload: &str, seq: &mut u64) -> String {
    if payload.contains("{seq}") {
        let s = payload.replace("{seq}", &seq.to_string());
        *seq = seq.wrapping_add(1);
        s
    } else {
        payload.to_string()
    }
}

// ── Status printers ───────────────────────────────────────────────────────────

fn print_main_status(ms: &MainState, cs: &ConnState) {
    println!("  client_id     = {}", ms.client_id);
    println!("  clean_session = {}", ms.clean_session);
    println!("  host          = {}:{}", cs.host, cs.port);
    println!("  keepalive     = {}s", cs.keepalive);
    match &cs.username {
        Some(u) => println!("  username      = {u}"),
        None => println!("  username      = (not set)"),
    }
    println!("  password      = {}", if cs.password.is_some() { "(set)" } else { "(not set)" });
    if let Some(w) = &cs.will {
        println!("  will.topic    = {}", w.topic);
        println!("  will.qos      = {}", w.qos);
        println!("  will.retain   = {}", w.retain);
    }
}

fn print_conn_status(ms: &MainState, cs: &ConnState) {
    print_main_status(ms, cs);
}

// ── Help text ─────────────────────────────────────────────────────────────────

fn print_main_help() {
    println!("  Main console commands:");
    println!("    client_id [<id>]          get/set MQTT client identifier");
    println!("    clean_session [true|false] get/set clean session flag");
    println!("    connection                 enter connection console");
    println!("    status                     show all current settings");
    println!("    exit / quit                exit shell");
}

fn print_conn_help() {
    println!("  Connection console commands:");
    println!("    host [<hostname>]          get/set broker host");
    println!("    port [<port>]              get/set broker port");
    println!("    keepalive [<seconds>]      get/set keepalive interval");
    println!("    username [<user>]          get/set username");
    println!("    clear_username             clear username");
    println!("    password                   set password (hidden input)");
    println!("    clear_password             clear password");
    println!("    will <topic> [payload [qos [retain]]]  set last will");
    println!("    clear_will                 clear last will");
    println!("    connect                    connect to broker");
    println!("    status                     show connection settings");
    println!("    exit / quit                return to main console");
}

fn print_msg_help() {
    println!("  Messaging console commands:");
    println!("    subscribe <topic> [qos]    subscribe (qos: 0/1/2, default 0)");
    println!("    unsubscribe <topic>        unsubscribe from topic");
    println!("    unsubscribe_all            unsubscribe from all topics");
    println!("    list_subscriptions / subs  list subscribed topics");
    println!("    publish <topic> [payload [qos [retain]]]  publish message");
    println!("      payload: use {{seq}} for auto-incrementing sequence number");
    println!("    listen [seconds]           print incoming messages for N seconds");
    println!("    logging on|off             toggle live message display");
    println!("    filter [pattern]           show only messages matching topic/payload substring");
    println!("    topics                     list unique topics seen with message count");
    println!("    ping                       send PINGREQ");
    println!("    disconnect                 disconnect and return to connection console");
    println!("    exit / quit                disconnect and exit shell");
}

// ── I/O helpers ───────────────────────────────────────────────────────────────

fn read_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(0) => Ok("exit".to_string()), // EOF (e.g. piped input exhausted)
        Ok(_) => Ok(line.trim().to_string()),
        Err(e) => Err(e.into()),
    }
}

fn read_password(prompt: &str) -> Result<String> {
    // Use dialoguer for hidden password input.
    dialoguer::Password::new().with_prompt(prompt.trim_end_matches(": ")).interact().map_err(Into::into)
}

fn split_first(s: &str) -> (&str, &str) {
    match s.find(' ') {
        Some(i) => (&s[..i], s[i + 1..].trim_start()),
        None => (s, ""),
    }
}
