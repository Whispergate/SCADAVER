//! Shared MQTT attack-utility functions used by both the shell and TUI.
//!
//! ACL probing, session-hijack, and retained-message hunt techniques are based on the
//! `HackTricks` MQTT pentesting guide
//! (<https://hacktricks.wiki/en/network-services-pentesting/1883-pentesting-mqtt-mosquitto.html>).

/// Classify an MQTT payload, returning a short format tag and a human-readable display string.
pub fn classify_payload(topic: &str, payload: &[u8]) -> (&'static str, String) {
    if topic.starts_with("spBv1.0/") || topic.starts_with("spAv1.0/") {
        let hex = payload.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        return ("sparkplug-b", hex);
    }
    if let Ok(s) = std::str::from_utf8(payload) {
        let t = s.trim();
        if t.starts_with('{') || t.starts_with('[') {
            return ("json", t.to_string());
        }
        if t.parse::<f64>().is_ok() {
            return ("number", t.to_string());
        }
        if t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("false") {
            return ("bool", t.to_string());
        }
        if payload.iter().all(|&b| b.is_ascii_graphic() || matches!(b, b' ' | b'\t' | b'\n' | b'\r')) {
            return ("text", t.to_string());
        }
        return ("utf8", t.to_string());
    }
    let hex = payload.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
    ("binary", hex)
}

/// Generate MQTT wildcard variants of a topic for ACL probing.
///
/// Returns the original topic plus variants with each segment replaced by `+`,
/// and `#` appended at each depth prefix. Deduplicates preserving order.
pub fn acl_variants(topic: &str) -> Vec<String> {
    let parts: Vec<&str> = topic.split('/').collect();
    let mut out = Vec::new();

    out.push(topic.to_string());

    for i in 0..parts.len() {
        let mut v = parts.clone();
        v[i] = "+";
        out.push(v.join("/"));
    }

    for depth in 0..=parts.len() {
        let v = if depth == 0 {
            "#".to_string()
        } else {
            format!("{}/#", parts[..depth].join("/"))
        };
        out.push(v);
    }

    let mut seen = std::collections::HashSet::new();
    out.retain(|v| seen.insert(v.clone()));
    out
}

/// Return true if a payload display string or topic contains credential or token patterns.
pub fn is_sensitive(display: &str, topic: &str) -> bool {
    if display.contains("eyJ") {
        return true; // JWT header (base64 encoded `{`)
    }
    let haystack = format!("{} {}", display.to_lowercase(), topic.to_lowercase());
    for kw in &["password", "passwd", "secret", "token", "credential", "apikey", "api_key"] {
        if haystack.contains(kw) {
            return true;
        }
    }
    false
}
