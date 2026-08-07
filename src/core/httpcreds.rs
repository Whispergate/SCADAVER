use crate::vendors::default_creds::ICS_HTTP_CREDS;
use base64::Engine as _;
use std::time::Duration;

pub struct CredResult {
    pub username: String,
    pub password: String,
    pub path: String,
    pub status: u16,
}

/// Try each entry from `ICS_HTTP_CREDS` against HTTP Basic Auth on `ip:port/path`.
/// Returns the first credential pair that receives a non-401/403 response.
pub fn test_http_basic(
    ip: &str,
    port: u16,
    path: &str,
    timeout_secs: u64,
) -> Option<CredResult> {
    let url = format!("http://{ip}:{port}{path}");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs.max(2)))
        .redirects(0)
        .build();

    for &(username, password) in ICS_HTTP_CREDS {
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
