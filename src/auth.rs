use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose, Engine};
use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

pub const DEFAULT_MAX_ATTEMPTS: usize = 3;
pub const HARD_MAX_ATTEMPTS: usize = 25;
pub const DEFAULT_DELAY_MS: u64 = 1_000;
pub const MIN_ACTIVE_DELAY_MS: u64 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    Siemens,
    Ewon,
    Schneider,
    Phoenix,
    BeckhoffWeb,
}

impl AuthProtocol {
    pub fn label(self) -> &'static str {
        match self {
            Self::Siemens => "siemens",
            Self::Ewon => "ewon",
            Self::Schneider => "schneider",
            Self::Phoenix => "phoenix",
            Self::BeckhoffWeb => "beckhoff-web",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Siemens => 102,
            Self::Ewon | Self::Schneider | Self::Phoenix => 80,
            Self::BeckhoffWeb => crate::vendors::beckhoff::webcontrol::DEFAULT_WEB_PORT,
        }
    }

    pub fn requires_username(self) -> bool {
        !matches!(self, Self::Siemens)
    }

    fn default_http_path(self) -> &'static str {
        match self {
            Self::Ewon => "/wrcgi.bin/wsdReadForm",
            Self::Schneider | Self::Phoenix | Self::BeckhoffWeb | Self::Siemens => "/",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Credential {
    pub username: Option<String>,
    pub password: String,
}

impl Credential {
    pub fn password_only(password: impl Into<String>) -> Self {
        Self {
            username: None,
            password: password.into(),
        }
    }

    pub fn pair(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: Some(username.into()),
            password: password.into(),
        }
    }

    pub fn redacted(&self) -> RedactedCredential<'_> {
        RedactedCredential(self)
    }
}

pub struct RedactedCredential<'a>(&'a Credential);

impl fmt::Display for RedactedCredential<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0.username {
            Some(username) => write!(f, "{username}:<redacted>"),
            None => write!(f, "<password redacted>"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStatus {
    Accepted,
    Rejected,
    LockoutSignal,
    NoAuthRequired,
    Unknown,
    NotApplicable,
}

impl AttemptStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::LockoutSignal => "lockout-signal",
            Self::NoAuthRequired => "no-auth-required",
            Self::Unknown => "unknown",
            Self::NotApplicable => "not-applicable",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AttemptResult {
    pub attempt: usize,
    pub credential: Option<Credential>,
    pub status: AttemptStatus,
    pub detail: String,
    pub retry_after: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthPolicy {
    pub max_attempts: usize,
    pub delay_ms: u64,
    pub stop_on_success: bool,
    pub stop_on_lockout: bool,
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            delay_ms: DEFAULT_DELAY_MS,
            stop_on_success: true,
            stop_on_lockout: true,
        }
    }
}

impl AuthPolicy {
    pub fn validate(&self, active: bool) -> Result<()> {
        if self.max_attempts == 0 {
            bail!("--max-attempts must be at least 1");
        }
        if self.max_attempts > HARD_MAX_ATTEMPTS {
            bail!("--max-attempts cannot exceed {HARD_MAX_ATTEMPTS}");
        }
        if active && self.delay_ms < MIN_ACTIVE_DELAY_MS {
            bail!("--delay-ms must be at least {MIN_ACTIVE_DELAY_MS} for active checks");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AuthReport {
    pub protocol: AuthProtocol,
    pub target: String,
    pub port: u16,
    pub active: bool,
    pub results: Vec<AttemptResult>,
    pub notes: Vec<String>,
}

impl AuthReport {
    pub fn new(protocol: AuthProtocol, target: &str, port: u16, active: bool) -> Self {
        Self {
            protocol,
            target: target.to_string(),
            port,
            active,
            results: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn attempted(&self) -> usize {
        self.results.iter().filter(|r| r.credential.is_some()).count()
    }

    pub fn accepted(&self) -> Option<&AttemptResult> {
        self.results
            .iter()
            .find(|r| r.status == AttemptStatus::Accepted)
    }

    pub fn lockout_signal(&self) -> Option<&AttemptResult> {
        self.results
            .iter()
            .find(|r| r.status == AttemptStatus::LockoutSignal)
    }
}

pub fn parse_combo(raw: &str, requires_username: bool) -> Result<Credential> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("empty credential entry");
    }

    if requires_username {
        let (user, pass) = raw
            .split_once(':')
            .or_else(|| raw.split_once(','))
            .ok_or_else(|| anyhow!("expected username:password"))?;
        let user = user.trim();
        if user.is_empty() {
            bail!("credential username cannot be empty");
        }
        return Ok(Credential::pair(user, pass.trim()));
    }

    let password = raw
        .split_once(':')
        .map_or(raw, |(_, pass)| pass)
        .trim()
        .to_string();
    Ok(Credential::password_only(password))
}

pub fn parse_combo_file(path: &Path, requires_username: bool) -> Result<Vec<Credential>> {
    let text = std::fs::read_to_string(path)?;
    let mut creds = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed = parse_combo(line, requires_username)
            .map_err(|e| anyhow!("{}:{}: {e}", path.display(), idx + 1))?;
        creds.push(parsed);
    }
    Ok(creds)
}

pub fn merge_dedup(creds: impl IntoIterator<Item = Credential>) -> Vec<Credential> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for cred in creds {
        let key = (
            cred.username.clone().unwrap_or_default().to_ascii_lowercase(),
            cred.password.clone(),
        );
        if seen.insert(key) {
            out.push(cred);
        }
    }
    out
}

pub fn config_credentials(protocol: AuthProtocol) -> Vec<Credential> {
    let loaded = crate::creds::load();
    match protocol {
        AuthProtocol::Siemens => loaded
            .siemens
            .passwords
            .into_iter()
            .map(Credential::password_only)
            .collect(),
        AuthProtocol::BeckhoffWeb => loaded
            .beckhoff
            .creds
            .into_iter()
            .map(|c| Credential::pair(c.username, c.password))
            .collect(),
        AuthProtocol::Schneider => loaded
            .schneider
            .creds
            .into_iter()
            .map(|c| Credential::pair(c.username, c.password))
            .collect(),
        AuthProtocol::Phoenix => loaded
            .phoenix
            .creds
            .into_iter()
            .map(|c| Credential::pair(c.username, c.password))
            .collect(),
        AuthProtocol::Ewon => Vec::new(),
    }
}

pub fn built_in_credentials(protocol: AuthProtocol) -> Vec<Credential> {
    match protocol {
        AuthProtocol::Siemens => crate::vendors::default_creds::default_passwords_for("siemens")
            .iter()
            .map(|pw| Credential::password_only(*pw))
            .collect(),
        AuthProtocol::BeckhoffWeb => pair_defaults("beckhoff"),
        AuthProtocol::Schneider => pair_defaults("schneider"),
        AuthProtocol::Phoenix => pair_defaults("phoenix"),
        AuthProtocol::Ewon => Vec::new(),
    }
}

fn pair_defaults(vendor: &str) -> Vec<Credential> {
    crate::vendors::default_creds::default_creds_for(vendor)
        .iter()
        .map(|(u, p)| Credential::pair(*u, *p))
        .collect()
}

pub fn collect_credentials(
    protocol: AuthProtocol,
    inline: &[String],
    files: &[PathBuf],
    use_config: bool,
    include_defaults: bool,
) -> Result<Vec<Credential>> {
    let mut creds = Vec::new();
    for raw in inline {
        creds.push(parse_combo(raw, protocol.requires_username())?);
    }
    for file in files {
        creds.extend(parse_combo_file(file, protocol.requires_username())?);
    }
    if use_config {
        creds.extend(config_credentials(protocol));
    }
    if include_defaults {
        creds.extend(built_in_credentials(protocol));
    }
    Ok(merge_dedup(creds))
}

pub fn check_credentials(
    protocol: AuthProtocol,
    target: &str,
    port: u16,
    active: bool,
    path: Option<&str>,
    credentials: &[Credential],
    policy: &AuthPolicy,
) -> Result<AuthReport> {
    policy.validate(active)?;
    let effective_port = if port == 0 { protocol.default_port() } else { port };
    let mut report = AuthReport::new(protocol, target, effective_port, active);

    if !active {
        passive_probe(&mut report, path);
        return Ok(report);
    }

    if credentials.is_empty() {
        bail!(
            "no credentials supplied; use --combo, --combo-file, --use-config, or --include-defaults"
        );
    }

    let capped: Vec<Credential> = credentials
        .iter()
        .take(policy.max_attempts)
        .cloned()
        .collect();
    if credentials.len() > capped.len() {
        report.notes.push(format!(
            "{} credential(s) skipped by max-attempts={}",
            credentials.len() - capped.len(),
            policy.max_attempts
        ));
    }

    match protocol {
        AuthProtocol::Siemens => active_siemens(&mut report, &capped, policy),
        AuthProtocol::Ewon
        | AuthProtocol::Schneider
        | AuthProtocol::Phoenix
        | AuthProtocol::BeckhoffWeb => active_http_basic(&mut report, &capped, policy, path),
    }

    Ok(report)
}

fn passive_probe(report: &mut AuthReport, path: Option<&str>) {
    match report.protocol {
        AuthProtocol::Siemens => {
            if crate::vendors::siemens::s7comm::probe_auth_required(&report.target, report.port, 5)
            {
                report.results.push(AttemptResult {
                    attempt: 0,
                    credential: None,
                    status: AttemptStatus::Unknown,
                    detail: "S7Comm access protection appears active".to_string(),
                    retry_after: None,
                });
            } else {
                report.results.push(AttemptResult {
                    attempt: 0,
                    credential: None,
                    status: AttemptStatus::NoAuthRequired,
                    detail: "No S7Comm access protection detected or target is unreachable".to_string(),
                    retry_after: None,
                });
            }
            report.notes.push(
                "S7Comm does not expose a standard lockout threshold enumeration signal"
                    .to_string(),
            );
        }
        AuthProtocol::Ewon
        | AuthProtocol::Schneider
        | AuthProtocol::Phoenix
        | AuthProtocol::BeckhoffWeb => {
            let probe = http_request(report.protocol, &report.target, report.port, path, None);
            report.results.push(AttemptResult {
                attempt: 0,
                credential: None,
                status: probe.status,
                detail: probe.detail,
                retry_after: probe.retry_after,
            });
            report.notes.push(
                "HTTP lockout detection is based on server status/body signals such as 423, 429, Retry-After, or lockout text"
                    .to_string(),
            );
        }
    }
}

fn active_siemens(report: &mut AuthReport, credentials: &[Credential], policy: &AuthPolicy) {
    if !crate::vendors::siemens::s7comm::probe_auth_required(&report.target, report.port, 5) {
        report.results.push(AttemptResult {
            attempt: 0,
            credential: None,
            status: AttemptStatus::NoAuthRequired,
            detail: "No S7Comm access protection detected; no password attempt needed".to_string(),
            retry_after: None,
        });
        return;
    }
    report.notes.push(
        "S7Comm password checks are password-only; usernames in supplied combos are ignored"
            .to_string(),
    );

    for (idx, cred) in credentials.iter().enumerate() {
        sleep_between_attempts(idx, policy.delay_ms);
        let state = crate::vendors::siemens::s7comm::get_cpu_state(
            &report.target,
            report.port,
            5,
            Some(&cred.password),
        );
        let status = if state == "Unknown" {
            AttemptStatus::Rejected
        } else {
            AttemptStatus::Accepted
        };
        report.results.push(AttemptResult {
            attempt: idx + 1,
            credential: Some(cred.clone()),
            status,
            detail: if status == AttemptStatus::Accepted {
                format!("Password accepted; CPU state: {state}")
            } else {
                "Password rejected or target did not return readable state".to_string()
            },
            retry_after: None,
        });
        if status == AttemptStatus::Accepted && policy.stop_on_success {
            break;
        }
    }
}

fn active_http_basic(
    report: &mut AuthReport,
    credentials: &[Credential],
    policy: &AuthPolicy,
    path: Option<&str>,
) {
    let unauth = http_request(report.protocol, &report.target, report.port, path, None);
    if unauth.status == AttemptStatus::NoAuthRequired {
        report.results.push(AttemptResult {
            attempt: 0,
            credential: None,
            status: AttemptStatus::NoAuthRequired,
            detail: "Selected HTTP path is reachable without authentication; credential acceptance cannot be proven".to_string(),
            retry_after: unauth.retry_after,
        });
        return;
    }
    if unauth.status == AttemptStatus::LockoutSignal {
        report.results.push(AttemptResult {
            attempt: 0,
            credential: None,
            status: AttemptStatus::LockoutSignal,
            detail: unauth.detail,
            retry_after: unauth.retry_after,
        });
        return;
    }

    for (idx, cred) in credentials.iter().enumerate() {
        sleep_between_attempts(idx, policy.delay_ms);
        let probe = http_request(report.protocol, &report.target, report.port, path, Some(cred));
        report.results.push(AttemptResult {
            attempt: idx + 1,
            credential: Some(cred.clone()),
            status: probe.status,
            detail: probe.detail,
            retry_after: probe.retry_after,
        });
        match probe.status {
            AttemptStatus::Accepted if policy.stop_on_success => break,
            AttemptStatus::LockoutSignal if policy.stop_on_lockout => break,
            _ => {}
        }
    }
}

fn sleep_between_attempts(idx: usize, delay_ms: u64) {
    if idx > 0 && delay_ms > 0 {
        thread::sleep(Duration::from_millis(delay_ms));
    }
}

#[derive(Debug, Clone)]
struct HttpProbe {
    status: AttemptStatus,
    detail: String,
    retry_after: Option<String>,
}

fn http_request(
    protocol: AuthProtocol,
    target: &str,
    port: u16,
    path: Option<&str>,
    credential: Option<&Credential>,
) -> HttpProbe {
    let path = path.unwrap_or_else(|| protocol.default_http_path());
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let url = format!("http://{target}:{port}{path}");
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(5))
        .build();
    let mut req = agent.get(&url);
    if let Some(cred) = credential {
        let user = cred.username.as_deref().unwrap_or("");
        let auth = general_purpose::STANDARD.encode(format!("{user}:{}", cred.password));
        req = req.set("Authorization", &format!("Basic {auth}"));
    }

    match req.call() {
        Ok(resp) => classify_http_response(
            resp.status(),
            resp.header("Retry-After").map(ToString::to_string),
            "",
            credential.is_none(),
        ),
        Err(ureq::Error::Status(code, resp)) => {
            let retry_after = resp.header("Retry-After").map(ToString::to_string);
            let body = resp.into_string().unwrap_or_default();
            classify_http_response(code, retry_after, &body, credential.is_none())
        }
        Err(e) => HttpProbe {
            status: AttemptStatus::Unknown,
            detail: format!("HTTP request failed: {e}"),
            retry_after: None,
        },
    }
}

fn classify_http_response(
    status: u16,
    retry_after: Option<String>,
    body: &str,
    unauthenticated: bool,
) -> HttpProbe {
    if is_http_lockout(status, retry_after.as_deref(), body) {
        return HttpProbe {
            status: AttemptStatus::LockoutSignal,
            detail: format!("HTTP {status} lockout/rate-limit signal"),
            retry_after,
        };
    }
    match status {
        200..=399 if unauthenticated => HttpProbe {
            status: AttemptStatus::NoAuthRequired,
            detail: format!("HTTP {status}; selected path is reachable without credentials"),
            retry_after,
        },
        200..=399 => HttpProbe {
            status: AttemptStatus::Accepted,
            detail: format!("HTTP {status}; credentials accepted by selected path"),
            retry_after,
        },
        401 | 403 => HttpProbe {
            status: AttemptStatus::Rejected,
            detail: format!("HTTP {status}; credentials rejected or access denied"),
            retry_after,
        },
        404 => HttpProbe {
            status: AttemptStatus::Unknown,
            detail: "HTTP 404; selected auth-check path does not exist".to_string(),
            retry_after,
        },
        _ => HttpProbe {
            status: AttemptStatus::Unknown,
            detail: format!("HTTP {status}; inconclusive auth response"),
            retry_after,
        },
    }
}

pub fn is_http_lockout(status: u16, retry_after: Option<&str>, body: &str) -> bool {
    if matches!(status, 423 | 429) || retry_after.is_some() {
        return true;
    }
    let body = body.to_ascii_lowercase();
    [
        "account locked",
        "account is locked",
        "too many attempts",
        "too many login",
        "rate limit",
        "rate-limit",
        "temporarily locked",
        "temporarily blocked",
        "try again later",
    ]
    .iter()
    .any(|needle| body.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_username_password_with_colon_password() {
        let cred = parse_combo("admin:pa:ss", true).unwrap();
        assert_eq!(cred.username.as_deref(), Some("admin"));
        assert_eq!(cred.password, "pa:ss");
    }

    #[test]
    fn parses_password_only_combo() {
        let cred = parse_combo("operator:secret", false).unwrap();
        assert_eq!(cred.username, None);
        assert_eq!(cred.password, "secret");
    }

    #[test]
    fn rejects_pair_without_username() {
        assert!(parse_combo(":secret", true).is_err());
    }

    #[test]
    fn dedupes_case_insensitive_usernames() {
        let creds = merge_dedup(vec![
            Credential::pair("Admin", "pw"),
            Credential::pair("admin", "pw"),
            Credential::pair("admin", "other"),
        ]);
        assert_eq!(creds.len(), 2);
    }

    #[test]
    fn policy_enforces_hard_cap_and_delay() {
        let policy = AuthPolicy {
            max_attempts: HARD_MAX_ATTEMPTS + 1,
            ..AuthPolicy::default()
        };
        assert!(policy.validate(true).is_err());

        let policy = AuthPolicy {
            delay_ms: MIN_ACTIVE_DELAY_MS - 1,
            ..AuthPolicy::default()
        };
        assert!(policy.validate(true).is_err());
        assert!(policy.validate(false).is_ok());
    }

    #[test]
    fn classifies_http_lockout_signals() {
        assert!(is_http_lockout(429, None, ""));
        assert!(is_http_lockout(401, Some("60"), ""));
        assert!(is_http_lockout(401, None, "Too many attempts"));
        assert!(!is_http_lockout(401, None, "Unauthorized"));
    }

    #[test]
    fn http_unauth_success_is_not_accepted_credentials() {
        let probe = classify_http_response(200, None, "", true);
        assert_eq!(probe.status, AttemptStatus::NoAuthRequired);
    }
}
