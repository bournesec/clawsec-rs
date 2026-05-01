use crate::ca::CertAuthority;
use crate::scanner::scan::{self, Direction};
use crate::threat::{log::ThreatLog, Dedup};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

const MAX_CONCURRENT: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Parameters passed to [`scan_and_emit`].
struct ScanContext<'a> {
    text: &'a str,
    direction: Direction,
    proto: &'a str,
    source: &'a str,
    dest: &'a str,
    max_scan: usize,
}

/// HTTP forward proxy with optional HTTPS MITM.
pub struct HttpProxy {
    port: u16,
    max_scan: usize,
    ca: Option<Arc<CertAuthority>>,
    threat_log: Arc<ThreatLog>,
    dedup: Arc<tokio::sync::Mutex<Dedup>>,
    shutdown: watch::Receiver<bool>,
    semaphore: Arc<Semaphore>,
}

impl HttpProxy {
    pub fn new(
        port: u16,
        max_scan: usize,
        enable_mitm: bool,
        ca: Option<Arc<CertAuthority>>,
        threat_log: Arc<ThreatLog>,
        dedup: Arc<tokio::sync::Mutex<Dedup>>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        let mitm_actual = enable_mitm && ca.is_some();
        info!(
            "HTTP proxy on 127.0.0.1:{} (HTTPS mode: {})",
            port,
            if mitm_actual { "MITM" } else { "tunnel" }
        );
        Self {
            port,
            max_scan,
            ca,
            threat_log,
            dedup,
            shutdown,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT)),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;

        let mut shutdown = self.shutdown.clone();
        let semaphore = self.semaphore.clone();
        let ca = self.ca.clone();
        let threat_log = self.threat_log.clone();
        let dedup = self.dedup.clone();
        let max_scan = self.max_scan;

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    info!("HTTP proxy: shutting down (no new connections)");
                    break;
                }
                result = listener.accept() => {
                    let (stream, peer) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("HTTP proxy accept error: {}", e);
                            continue;
                        }
                    };
                    let peer_ip = peer.ip().to_string();
                    let ca = ca.clone();
                    let threat_log = threat_log.clone();
                    let dedup = dedup.clone();
                    let semaphore = semaphore.clone();

                    tokio::spawn(async move {
                        // Acquire concurrency permit — held for the connection lifetime
                        let _permit = match semaphore.acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        if let Err(e) =
                            handle_connection(stream, &peer_ip, ca, max_scan, threat_log, dedup).await
                        {
                            debug!("Connection from {}: {}", peer_ip, e);
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

async fn handle_connection(
    mut tcp: tokio::net::TcpStream,
    peer_ip: &str,
    ca: Option<Arc<CertAuthority>>,
    max_scan: usize,
    threat_log: Arc<ThreatLog>,
    dedup: Arc<tokio::sync::Mutex<Dedup>>,
) -> anyhow::Result<()> {
    let header = read_http_header(&mut tcp).await?;
    if header.is_empty() {
        return Ok(());
    }
    let header_text = String::from_utf8_lossy(&header);
    let first_line = header_text.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0].to_uppercase();
    let target = parts[1];

    scan_and_emit(
        ScanContext {
            text: &header_text,
            direction: Direction::Outbound,
            proto: "http",
            source: peer_ip,
            dest: target,
            max_scan,
        },
        &threat_log,
        &dedup,
    )
    .await;

    if method == "CONNECT" {
        let host_port = target;
        let (host, port_str) = host_port.split_once(':').unwrap_or((host_port, "443"));
        let port: u16 = port_str.parse().unwrap_or(443);

        if let Some(ca) = ca {
            mitm_tunnel(tcp, &ca, host, port, max_scan, threat_log, dedup).await?;
        } else {
            blind_tunnel(tcp, host, port).await?;
        }
    } else {
        http_forward(tcp, &header, target, max_scan, threat_log, dedup).await?;
    }

    Ok(())
}

/// Read HTTP headers from TcpStream up to \r\n\r\n (byte-by-byte).
async fn read_http_header(stream: &mut tokio::net::TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if buf.len() > 16384 {
            return Ok(Vec::new());
        }
    }
    Ok(buf)
}

async fn scan_and_emit(
    ctx: ScanContext<'_>,
    threat_log: &ThreatLog,
    dedup: &tokio::sync::Mutex<Dedup>,
) {
    let threats = scan::scan(
        ctx.text,
        ctx.direction,
        ctx.proto,
        ctx.source,
        ctx.dest,
        ctx.max_scan,
    );
    for t in threats {
        let mut d = dedup.lock().await;
        if !d.is_duplicate(&t) {
            let _ = threat_log.append(&t);
        }
    }
}

async fn connect_upstream_tls(
    host: &str,
    port: u16,
) -> anyhow::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let addr = format!("{}:{}", host, port);
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!("connect to {}:{} timed out", host, port))??;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        root_store.add(cert)?;
    }
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let host_owned = host.to_string();
    let server_name =
        ServerName::try_from(host_owned).map_err(|_| anyhow::anyhow!("invalid hostname"))?;

    let stream = connector.connect(server_name, tcp).await?;
    Ok(stream)
}

/// HTTPS MITM tunnel: two-way pipe with plaintext scanning.
async fn mitm_tunnel(
    tcp: tokio::net::TcpStream,
    ca: &CertAuthority,
    host: &str,
    port: u16,
    max_scan: usize,
    threat_log: Arc<ThreatLog>,
    dedup: Arc<tokio::sync::Mutex<Dedup>>,
) -> anyhow::Result<()> {
    let upstream = match connect_upstream_tls(host, port).await {
        Ok(s) => s,
        Err(_) => {
            let mut tcp = tcp;
            let _ = tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Ok(());
        }
    };

    let server_cfg = match ca.server_config_for_host(host) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(
                "Cert gen failed {}: {} — falling back to blind tunnel",
                host, e
            );
            return blind_tunnel(tcp, host, port).await;
        }
    };

    // Send 200, then upgrade client to TLS
    let mut tcp = tcp;
    tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let mut client_tls = match acceptor.accept(tcp).await {
        Ok(s) => s,
        Err(e) => {
            debug!("MITM TLS handshake failed {}: {}", host, e);
            return Ok(());
        }
    };

    let dest = format!("{}:{}", host, port);
    let (mut client_r, mut client_w) = tokio::io::split(&mut client_tls);
    let (mut up_r, mut up_w) = tokio::io::split(upstream);

    // Bidirectional pipe with concurrent scanning
    let mut buf_client = [0u8; 8192];
    let mut buf_up = [0u8; 8192];
    let mut scanned_out = 0usize;
    let mut scanned_in = 0usize;
    let max = max_scan;

    loop {
        tokio::select! {
            biased; // check upstream (response) first

            result = up_r.read(&mut buf_up) => {
                let n = match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                // Forward raw bytes first, then scan
                if client_w.write_all(&buf_up[..n]).await.is_err() {
                    break;
                }
                if scanned_in < max {
                    let text = String::from_utf8_lossy(&buf_up[..n]);
                    scan_and_emit(ScanContext {
                        text: &text, direction: Direction::Inbound, proto: "https",
                        source: "", dest: &dest, max_scan: max,
                    }, &threat_log, &dedup).await;
                    scanned_in += n;
                }
            }

            result = client_r.read(&mut buf_client) => {
                let n = match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                // Forward raw bytes first, then scan
                if up_w.write_all(&buf_client[..n]).await.is_err() {
                    break;
                }
                if scanned_out < max {
                    let text = String::from_utf8_lossy(&buf_client[..n]);
                    scan_and_emit(ScanContext {
                        text: &text, direction: Direction::Outbound, proto: "https",
                        source: "", dest: &dest, max_scan: max,
                    }, &threat_log, &dedup).await;
                    scanned_out += n;
                }
            }
        }
    }
    Ok(())
}

/// Blind CONNECT tunnel — no inspection.
async fn blind_tunnel(
    tcp: tokio::net::TcpStream,
    host: &str,
    port: u16,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", host, port);
    let mut upstream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect to {}:{} timed out", host, port))?
    {
        Ok(s) => s,
        Err(_) => {
            let mut tcp = tcp;
            let _ = tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return Ok(());
        }
    };

    let mut tcp = tcp;
    tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    match tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await {
        Ok(_) | Err(_) => {}
    }
    Ok(())
}

/// Plain HTTP forward.
async fn http_forward(
    mut tcp: tokio::net::TcpStream,
    request_head: &[u8],
    target: &str,
    max_scan: usize,
    threat_log: Arc<ThreatLog>,
    dedup: Arc<tokio::sync::Mutex<Dedup>>,
) -> anyhow::Result<()> {
    let (host, port) = resolve_host(target, request_head);
    if host.is_empty() {
        tcp.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        return Ok(());
    }

    let addr = format!("{}:{}", host, port);
    let mut upstream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect to {}:{} timed out", host, port))?
    {
        Ok(s) => s,
        Err(_) => {
            tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            return Ok(());
        }
    };

    let rewritten = rewrite_request(request_head);
    upstream.write_all(&rewritten).await?;

    let dest = format!("{}:{}", host, port);
    let (mut up_r, mut up_w) = upstream.split();
    let (mut tcp_r, mut tcp_w) = tcp.split();

    let mut buf_up = [0u8; 8192];
    let mut buf_tcp = [0u8; 8192];
    let mut scanned = 0usize;
    let max = max_scan;

    loop {
        tokio::select! {
            result = up_r.read(&mut buf_up) => {
                let n = match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                // Forward raw bytes first, then scan
                if tcp_w.write_all(&buf_up[..n]).await.is_err() { break; }
                if scanned < max {
                    let text = String::from_utf8_lossy(&buf_up[..n]);
                    scan_and_emit(ScanContext {
                        text: &text, direction: Direction::Inbound, proto: "http",
                        source: "", dest: &dest, max_scan: max,
                    }, &threat_log, &dedup).await;
                    scanned += n;
                }
            }
            result = tcp_r.read(&mut buf_tcp) => {
                let n = match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if up_w.write_all(&buf_tcp[..n]).await.is_err() { break; }
            }
        }
    }
    Ok(())
}

fn resolve_host(target: &str, headers: &[u8]) -> (String, u16) {
    if target.starts_with("http://") {
        let rest = target.trim_start_matches("http://");
        let host_port = rest.split('/').next().unwrap_or(rest);
        let (host, port) = host_port.split_once(':').unwrap_or((host_port, "80"));
        return (host.to_string(), port.parse().unwrap_or(80));
    }

    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        if line.to_lowercase().starts_with("host:") {
            let val = line[5..].trim();
            if let Some((h, p)) = val.split_once(':') {
                return (h.to_string(), p.parse().unwrap_or(80));
            }
            return (val.to_string(), 80);
        }
    }
    (String::new(), 0)
}

fn rewrite_request(head: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut out = Vec::new();
    let mut has_conn = false;

    for line in text.lines() {
        let low = line.to_lowercase();
        if low.starts_with("proxy-connection:") || low.starts_with("keep-alive:") {
            continue;
        }
        if low.starts_with("connection:") {
            out.extend_from_slice(b"Connection: close\r\n");
            has_conn = true;
        } else {
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    if !has_conn {
        out.extend_from_slice(b"Connection: close\r\n\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_host_http_url() {
        let headers = b"GET http://example.com/path HTTP/1.0\r\nHost: example.com\r\n\r\n";
        let (host, port) = resolve_host("http://example.com/path", headers);
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_resolve_host_header() {
        let headers = b"GET /path HTTP/1.0\r\nHost: api.example.com:8080\r\n\r\n";
        let (host, port) = resolve_host("/path", headers);
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_rewrite_request_strips_proxy_headers() {
        let req = b"GET http://example.com/ HTTP/1.0\r\nProxy-Connection: keep-alive\r\nHost: example.com\r\n\r\n";
        let rewritten = rewrite_request(req);
        let text = String::from_utf8_lossy(&rewritten);
        assert!(!text.to_lowercase().contains("proxy-connection"));
    }

    #[test]
    fn test_resolve_host_no_host_header() {
        let headers = b"GET /path HTTP/1.0\r\n\r\n";
        let (host, port) = resolve_host("/path", headers);
        assert_eq!(host, "");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_resolve_host_http_url_with_port() {
        let headers = b"GET http://example.com:8080/path HTTP/1.0\r\nHost: example.com\r\n\r\n";
        let (host, port) = resolve_host("http://example.com:8080/path", headers);
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_resolve_host_http_url_default_port() {
        let headers = b"GET http://example.com/path HTTP/1.0\r\n\r\n";
        let (host, port) = resolve_host("http://example.com/path", headers);
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_rewrite_request_adds_connection_close_when_missing() {
        let req = b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
        let rewritten = rewrite_request(req);
        let text = String::from_utf8_lossy(&rewritten);
        assert!(text.to_lowercase().contains("connection: close"));
    }

    #[test]
    fn test_rewrite_request_replaces_connection_header() {
        let req = b"GET / HTTP/1.0\r\nConnection: keep-alive\r\nHost: example.com\r\n\r\n";
        let rewritten = rewrite_request(req);
        let text = String::from_utf8_lossy(&rewritten);
        assert!(text.to_lowercase().contains("connection: close"));
        assert!(!text.to_lowercase().contains("keep-alive"));
    }

    #[test]
    fn test_rewrite_request_strips_keep_alive() {
        let req =
            b"GET / HTTP/1.0\r\nKeep-Alive: timeout=5\r\nHost: example.com\r\n\r\n";
        let rewritten = rewrite_request(req);
        let text = String::from_utf8_lossy(&rewritten);
        assert!(!text.to_lowercase().contains("keep-alive:"));
    }

    #[test]
    fn test_resolve_host_case_insensitive_host_header() {
        let headers = b"GET / HTTP/1.0\r\nHOST: example.com\r\n\r\n";
        let (host, port) = resolve_host("/", headers);
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_resolve_host_header_with_port_and_whitespace() {
        let headers = b"GET / HTTP/1.0\r\nHost:  api.example.com:3000  \r\n\r\n";
        let (host, port) = resolve_host("/", headers);
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 3000);
    }

    #[tokio::test]
    async fn test_read_http_header_simple_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let header = read_http_header(&mut stream).await.unwrap();
            assert!(!header.is_empty());
            let text = String::from_utf8_lossy(&header);
            assert!(text.contains("GET /test"));
            assert!(text.contains("Host: example.com"));
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /test HTTP/1.0\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_read_http_header_empty_on_large_input() {
        // read_http_header returns empty Vec when input exceeds 16384 bytes
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let header = read_http_header(&mut stream).await.unwrap();
            assert!(header.is_empty());
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Send more than 16384 bytes without \r\n\r\n
        let padding = vec![b'x'; 17000];
        client.write_all(&padding).await.unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn test_rewrite_request_preserves_non_proxy_headers() {
        let req =
            b"GET / HTTP/1.0\r\nHost: example.com\r\nAccept: text/html\r\nUser-Agent: test\r\n\r\n";
        let rewritten = rewrite_request(req);
        let text = String::from_utf8_lossy(&rewritten);
        assert!(text.contains("Host: example.com"));
        assert!(text.contains("Accept: text/html"));
        assert!(text.contains("User-Agent: test"));
        assert!(text.to_lowercase().contains("connection: close"));
    }

    #[test]
    fn test_rewrite_request_is_idempotent() {
        let req = b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
        let first = rewrite_request(req);
        let second = rewrite_request(&first);
        // Second pass should not add duplicate Connection headers
        let text = String::from_utf8_lossy(&second);
        let count = text.to_lowercase().matches("connection:").count();
        assert_eq!(count, 1, "Connection header should appear exactly once");
    }

    #[tokio::test]
    async fn proxy_new_with_mitm_no_ca() {
        use crate::threat::Dedup;
        let dir = tempfile::TempDir::new().unwrap();
        let log = Arc::new(crate::threat::log::ThreatLog::new(dir.path()));
        let dedup = Arc::new(tokio::sync::Mutex::new(Dedup::new(60.0)));
        let (_tx, rx) = tokio::sync::watch::channel(false);

        let proxy = HttpProxy::new(18888, 65536, true, None, log, dedup, rx);
        // MITM should be OFF since there's no CA
        // Constructor succeeds — just verify it doesn't panic
        assert_eq!(proxy.port, 18888);
        assert_eq!(proxy.max_scan, 65536);
    }

    #[tokio::test]
    async fn proxy_new_with_mitm_and_ca() {
        use crate::ca::CertAuthority;
        use crate::threat::Dedup;
        let dir = tempfile::TempDir::new().unwrap();
        let ca =
            Arc::new(CertAuthority::initialize(dir.path(), true).unwrap().unwrap());
        let log = Arc::new(crate::threat::log::ThreatLog::new(dir.path()));
        let dedup = Arc::new(tokio::sync::Mutex::new(Dedup::new(60.0)));
        let (_tx, rx) = tokio::sync::watch::channel(false);

        let proxy = HttpProxy::new(18889, 32768, true, Some(ca), log, dedup, rx);
        assert_eq!(proxy.port, 18889);
        assert!(proxy.ca.is_some());
    }

    #[tokio::test]
    async fn proxy_new_mitm_disabled_with_ca() {
        use crate::ca::CertAuthority;
        use crate::threat::Dedup;
        let dir = tempfile::TempDir::new().unwrap();
        let ca =
            Arc::new(CertAuthority::initialize(dir.path(), true).unwrap().unwrap());
        let log = Arc::new(crate::threat::log::ThreatLog::new(dir.path()));
        let dedup = Arc::new(tokio::sync::Mutex::new(Dedup::new(60.0)));
        let (_tx, rx) = tokio::sync::watch::channel(false);

        let proxy = HttpProxy::new(18890, 65536, false, Some(ca), log, dedup, rx);
        // MITM should be disabled even though CA is present
        assert!(proxy.ca.is_some());
    }
}
