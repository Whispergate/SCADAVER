pub mod routes;

use anyhow::Result;

/// Start the web interface. Blocks until the server is stopped (Ctrl-C).
pub fn start(host: &str, port: u16) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create async runtime: {e}"))?;
    rt.block_on(run(host, port))
}

async fn run(host: &str, port: u16) -> Result<()> {
    let addr: std::net::SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid listen address '{host}:{port}': {e}"))?;

    let app = routes::build_router();
    let url = format!("http://{addr}");
    println!("[*] SCADAver web interface → {url}");
    println!("[*] Press Ctrl-C to stop.");

    let url_clone = url.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(600));
        open_browser(&url_clone);
    });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Cannot bind to {addr}: {e}"))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {e}"))
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
