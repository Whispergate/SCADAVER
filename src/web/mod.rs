pub mod routes;

use anyhow::Result;

/// Start the web interface. Blocks until the server is stopped (Ctrl-C).
/// `api_key`: when `Some`, uses a fixed key (from config); when `None`, auto-generates per session.
pub fn start(host: &str, port: u16, api_key: Option<String>) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create async runtime: {e}"))?;
    rt.block_on(run(host, port, api_key))
}

fn generate_token() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
        s
    })
}

async fn run(host: &str, port: u16, api_key: Option<String>) -> Result<()> {
    let addr: std::net::SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid listen address '{host}:{port}': {e}"))?;

    let token = test_api_key().or(api_key).unwrap_or_else(generate_token);
    let app = routes::build_router(token.clone());
    let url = format!("http://{addr}");
    println!("[*] SCADAver web interface - {url}/?key={token}");
    println!("[*] API key: {token}  (required for write/exploit endpoints)");
    println!("[*] Press Ctrl-C to stop.");

    if !no_browser_requested() {
        let url_with_key = format!("{url}/?key={token}");
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(600));
            open_browser(&url_with_key);
        });
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Cannot bind to {addr}: {e}"))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))
}

/// Browser automation uses this to prevent an interactive window from opening.
/// It is also useful for a deliberately headless local deployment.
fn no_browser_requested() -> bool {
    std::env::var("SCADAVER_NO_BROWSER").as_deref() == Ok("1")
}

/// The deterministic API key is deliberately limited to the loopback-only test
/// harness. Regular starts still use configured keys or a random session token.
fn test_api_key() -> Option<String> {
    if std::env::var("SCADAVER_TEST_LOOPBACK").as_deref() != Ok("1") {
        return None;
    }
    std::env::var("SCADAVER_TEST_API_KEY")
        .ok()
        .filter(|key| !key.is_empty())
}

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}
