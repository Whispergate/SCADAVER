//! Interactive MQTT client shell for broker reconnaissance and testing.
//!
//! Based on python-mqtt-client-shell by Barry Powell
//! (<https://github.com/bapowell/python-mqtt-client-shell>)

use anyhow::Result;
use std::collections::HashMap;
use std::io::{self, Write};
use std::time::Duration;
use std::thread;

use scadaver::vendors::mqtt::client;
use scadaver::vendors::mqtt::session::{ConnectOptions, MqttMessage, MqttSession, WillConfig};
use scadaver::vendors::mqtt::sparkplug_fuzz::{FuzzCategory, FuzzConfig, run_sparkplug_fuzz};

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

fn drain_and_log(
    session: &MqttSession,
    topic_stats: &mut HashMap<String, usize>,
    retained_cache: &mut HashMap<String, String>,
    logging: bool,
    filter: &str,
) {
    for msg in session.drain_messages() {
        *topic_stats.entry(msg.topic.clone()).or_insert(0) += 1;
        if msg.retain {
            let (_, display) = detect_payload(&msg.topic, &msg.payload);
            retained_cache.insert(msg.topic.clone(), display);
        }
        if logging && matches_filter(&msg, filter) {
            let (fmt, display) = detect_payload(&msg.topic, &msg.payload);
            println!();
            println!(
                "  [{}] {} : {}  [{}]",
                if msg.retain { "R" } else { " " },
                msg.topic,
                display,
                fmt
            );
        }
    }
}

fn messaging_console(cs: &ConnState, mut session: MqttSession) -> Result<()> {
    let mut logging = true;
    let mut seq: u64 = 0;
    let mut filter = String::new();
    let mut topic_stats: HashMap<String, usize> = HashMap::new();
    let mut retained_cache: HashMap<String, String> = HashMap::new();
    println!("  Logging is ON.  Incoming messages will appear before each prompt.");
    println!("  Type 'help' for commands.");
    println!();

    if let Err(e) = session.subscribe("#", 0) {
        println!("  warning: could not subscribe to '#': {e:#}");
    } else {
        println!("  auto-subscribed to '#' (QoS 0) — use 'subscribe'/'unsubscribe' to adjust.");
    }
    println!();

    loop {
        drain_and_log(&session, &mut topic_stats, &mut retained_cache, logging, &filter);

        let line = read_line("mqtt/messaging> ")?;
        let (cmd, rest) = split_first(&line);

        match cmd {
            "filter" => apply_filter_cmd(&mut filter, rest),
            "topics" => show_topics(&topic_stats),
            "tree" => show_topic_tree(&topic_stats),
            "retained" => show_retained(&retained_cache),
            "sys" => handle_sys_cmd(&mut session, &mut topic_stats),
            "creds" => handle_creds_cmd(cs, rest),
            "spfuzz" => handle_spfuzz_cmd(&mut session, cs, rest),
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
            "listen" => handle_listen_cmd(&session, rest, &filter, &mut topic_stats, &mut retained_cache),
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
    retained_cache: &mut HashMap<String, String>,
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
            if msg.retain {
                let (_, display) = detect_payload(&msg.topic, &msg.payload);
                retained_cache.insert(msg.topic.clone(), display);
            }
            if matches_filter(&msg, filter) {
                let (fmt, display) = detect_payload(&msg.topic, &msg.payload);
                println!(
                    "  [{}] {} : {}  [{}]",
                    if msg.retain { "R" } else { " " },
                    msg.topic,
                    display,
                    fmt
                );
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

fn handle_sys_cmd(session: &mut MqttSession, topic_stats: &mut HashMap<String, usize>) {
    if let Err(e) = session.subscribe("$SYS/#", 0) {
        println!("  subscribe failed: {e:#}");
        return;
    }
    println!("  Fetching $SYS stats (2s)…");
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut count = 0usize;
    while std::time::Instant::now() < deadline {
        for msg in session.drain_messages() {
            *topic_stats.entry(msg.topic.clone()).or_insert(0) += 1;
            if msg.topic.starts_with("$SYS/") {
                let (_, display) = detect_payload(&msg.topic, &msg.payload);
                println!("  {:<46} : {}", msg.topic, display);
                count += 1;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    println!("  {count} stat(s) received.");
}

const DEFAULT_CREDS: &[(&str, &str)] = &[
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "1234"),
    ("admin",  ""),
    ("mqtt",   "mqtt"),
    ("mqtt",   "password"),
    ("user",   "user"),
    ("guest",  "guest"),
    ("test",   "test"),
    ("root",   "root"),
    ("admin",  "admin1234"),
    ("admin",  "mosquitto"),
];

fn handle_creds_cmd(cs: &ConnState, extra: &str) {
    let pairs: Vec<(&str, &str)> = if extra.is_empty() {
        DEFAULT_CREDS.to_vec()
    } else {
        extra.split_once(':')
            .map(|(u, p)| vec![(u, p)])
            .unwrap_or_default()
    };
    if pairs.is_empty() {
        println!("  usage: creds [user:pass]");
        return;
    }
    println!("  Testing {} credential pair(s) against {}:{}…", pairs.len(), cs.host, cs.port);
    let mut hits = 0usize;
    for (user, pass) in &pairs {
        match client::try_credential(&cs.host, cs.port, user, pass) {
            Some(true) => {
                println!("  [+] {user} : {pass}  <- ACCEPTED");
                hits += 1;
            }
            Some(false) => println!("  [-] {user} : {pass}"),
            None => println!("  [?] {user} : {pass}  (network error)"),
        }
    }
    if hits == 0 {
        println!("  no valid credentials found.");
    } else {
        println!("  {hits} valid credential(s) found.");
    }
}

fn handle_spfuzz_cmd(session: &mut MqttSession, cs: &ConnState, args: &str) {
    let mut config = FuzzConfig::default();
    let mut tokens = args.split_whitespace().peekable();
    let mut parse_categories = false;

    while let Some(tok) = tokens.next() {
        match tok {
            "--delay" => {
                if let Some(v) = tokens.next().and_then(|s| s.parse::<u64>().ok()) {
                    config.delay_ms = v;
                } else {
                    println!("  usage: spfuzz --delay <ms>");
                    return;
                }
            }
            "--discovery" => {
                if let Some(v) = tokens.next().and_then(|s| s.parse::<u32>().ok()) {
                    config.discovery_secs = v;
                } else {
                    println!("  usage: spfuzz --discovery <seconds>");
                    return;
                }
            }
            "--probe-write" => {
                config.probe_write = true;
            }
            "--dry-run" => {
                config.dry_run = true;
            }
            "--categories" => {
                config.categories.clear();
                parse_categories = true;
            }
            // Help must appear before the parse_categories guard so "spfuzz help"
            // works even when --categories was already seen.
            "--help" | "-h" | "help" => {
                print_spfuzz_help();
                return;
            }
            tok if parse_categories => {
                if tok.starts_with("--") {
                    println!("  unknown flag '{tok}'. Type 'spfuzz help' for usage.");
                    return;
                }
                if let Some(cat) = FuzzCategory::parse(tok) {
                    config.categories.push(cat);
                } else {
                    println!("  unknown category '{tok}'. Valid: topic malformed boundary ordering sequence");
                    return;
                }
            }
            _ => {
                println!("  unknown flag '{tok}'. Type 'spfuzz help' for usage.");
                return;
            }
        }
    }

    if config.categories.is_empty() {
        println!("  no categories selected after --categories. Valid: topic malformed boundary ordering sequence");
        return;
    }

    let no_creds = cs.username.is_none();
    if let Err(e) = run_sparkplug_fuzz(session, &cs.host, cs.port, no_creds, &config) {
        println!("  spfuzz error: {e:#}");
    }
}

fn print_spfuzz_help() {
    println!("  spfuzz — Sparkplug B protocol fuzzer (authorized use only)");
    println!();
    println!("  Usage: spfuzz [OPTIONS]");
    println!();
    println!("  Options:");
    println!("    --delay <ms>             delay between messages (min 50, default 100)");
    println!("    --discovery <s>          passive listen time before fuzzing (min 5, default 10)");
    println!("    --probe-write            enable targeted spoofing against discovered devices");
    println!("    --dry-run                print what would be sent without publishing anything");
    println!("    --categories <list>      space-separated categories to run (default: topic malformed boundary)");
    println!("      Valid categories: topic  malformed  boundary  ordering  sequence");
    println!("    help                     show this help");
    println!();
    println!("  Safety notes:");
    println!("    Always run --dry-run first to review the payload list");
    println!("    NBIRTH+DBIRTH are published before fuzz categories (protocol compliance)");
    println!("    NDEATH is published at the end of every run (clean broker state)");
    println!("    All messages use QoS 0 and retain=false");
    println!();
    println!("  Examples:");
    println!("    spfuzz --dry-run                         preview all messages without sending");
    println!("    spfuzz                                   run with defaults");
    println!("    spfuzz --delay 500 --discovery 30        slower pace, longer discovery");
    println!("    spfuzz --categories topic malformed      only those two categories");
    println!("    spfuzz --probe-write                     enable targeted device spoofing");
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

fn show_topic_tree(topic_stats: &HashMap<String, usize>) {
    if topic_stats.is_empty() {
        println!("  (no messages received yet)");
        return;
    }
    let mut topics: Vec<(&String, &usize)> = topic_stats.iter().collect();
    topics.sort_by_key(|(t, _)| t.as_str());
    let mut printed: Vec<String> = Vec::new();
    for (topic, count) in &topics {
        let parts: Vec<&str> = topic.split('/').collect();
        for depth in 0..parts.len() {
            let prefix = parts[..=depth].join("/");
            if printed.contains(&prefix) {
                continue;
            }
            printed.push(prefix.clone());
            let indent = "  ".repeat(depth + 1);
            if depth == parts.len() - 1 {
                println!("  {indent}{:<36} {count}", parts[depth]);
            } else {
                println!("  {indent}{}/", parts[depth]);
            }
        }
    }
    let total: usize = topic_stats.values().sum();
    println!("  {} topic(s), {} message(s) total", topic_stats.len(), total);
}

fn show_retained(cache: &HashMap<String, String>) {
    if cache.is_empty() {
        println!("  (no retained messages seen yet)");
        return;
    }
    let mut rows: Vec<(&String, &String)> = cache.iter().collect();
    rows.sort_by_key(|(t, _)| t.as_str());
    println!("  {:<44} last retained payload", "topic");
    println!("  {}", "─".repeat(62));
    for (topic, payload) in &rows {
        println!("  {topic:<44} {payload}");
    }
    println!("  {} retained topic(s)", rows.len());
}

fn matches_filter(msg: &MqttMessage, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    let f = filter.to_lowercase();
    msg.topic.to_lowercase().contains(&f) || msg.payload_str().to_lowercase().contains(&f)
}

fn detect_payload(topic: &str, payload: &[u8]) -> (&'static str, String) {
    if topic.starts_with("spBv1.0/") || topic.starts_with("spAv1.0/") {
        let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        return ("sparkplug-b", hex);
    }
    if let Ok(s) = std::str::from_utf8(payload) {
        let trimmed = s.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return ("json", trimmed.to_string());
        }
        if trimmed.parse::<f64>().is_ok() {
            return ("number", trimmed.to_string());
        }
        if trimmed.eq_ignore_ascii_case("true") || trimmed.eq_ignore_ascii_case("false") {
            return ("bool", trimmed.to_string());
        }
        if payload.iter().all(|&b| (0x20u8..0x7F).contains(&b)) {
            return ("text", trimmed.to_string());
        }
        return ("utf8", trimmed.to_string());
    }
    let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
    ("binary", hex)
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
    println!("    tree                       show observed topics as an indented hierarchy");
    println!("    retained                   list topics with broker-retained payloads seen so far");
    println!("    sys                        subscribe to $SYS/# and display broker statistics");
    println!("    creds [user:pass]          test default MQTT credentials (or one specific pair)");
    println!("    spfuzz [options]           Sparkplug B fuzzer (run --dry-run first! see 'spfuzz help')");
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
