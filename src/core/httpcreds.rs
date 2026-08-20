use crate::vendors::default_creds::ICS_HTTP_CREDS;
use base64::Engine as _;
use std::time::Duration;

pub struct CredResult {
    pub username: String,
    pub password: String,
    pub path: String,
    pub status: u16,
}

/// Try each credential pair against HTTP Basic Auth on `ip:port/path`.
///
/// `extra_creds` are tried first (custom wordlist / creds.toml entries), followed by the
/// compiled-in `ICS_HTTP_CREDS` defaults. Returns the first pair that receives a
/// non-401/403 response.
pub fn test_http_basic(
    ip: &str,
    port: u16,
    path: &str,
    timeout_secs: u64,
    extra_creds: &[(String, String)],
) -> Option<CredResult> {
    let url = format!("http://{ip}:{port}{path}");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs.max(2)))
        .redirects(0)
        .build();

    let custom = extra_creds.iter().map(|(u, p)| (u.as_str(), p.as_str()));
    let builtin = ICS_HTTP_CREDS.iter().map(|&(u, p)| (u, p));

    for (username, password) in custom.chain(builtin) {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{username}:{password}"));
        match agent
            .get(&url)
            .set("Authorization", &format!("Basic {encoded}"))
            .call()
        {
            Ok(resp) => {
                let status = resp.status();
                if status != 401 && status != 403 {
                    return Some(CredResult {
                        username: username.to_string(),
                        password: password.to_string(),
                        path: path.to_string(),
                        status,
                    });
                }
            }
            // A redirect (3xx) also counts as a successful auth.
            Err(ureq::Error::Status(code, _)) if (200..400).contains(&code) => {
                return Some(CredResult {
                    username: username.to_string(),
                    password: password.to_string(),
                    path: path.to_string(),
                    status: code,
                });
            }
            Err(_) => {}
        }
    }
    None
}
