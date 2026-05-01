//! ClawSec Monitor core library.
//!
//! Provides the `Monitor` struct for lifecycle management of the HTTP proxy,
//! SSH watcher, and threat detection engine. Used by both the CLI binary
//! (`clawsec`) and the Tauri desktop application.

pub mod ca;
pub mod config;
pub mod pid;
pub mod proxy;
pub mod scanner;
pub mod ssh_watcher;
pub mod threat;

use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use tracing::info;

/// Structured status returned by the monitor.
#[derive(Debug, serde::Serialize)]
pub struct Status {
    pub running: bool,
    pub pid: Option<u32>,
    pub total_threats: usize,
}

/// Encapsulates the full ClawSec Monitor lifecycle.
///
/// Manages the HTTP proxy, SSH watcher, CA certificates, PID file, and
/// graceful shutdown. Designed to be used from both CLI and Tauri.
pub struct Monitor {
    pub config: config::Config,
    pub ca: Option<Arc<ca::CertAuthority>>,
    pub threat_log: Arc<threat::log::ThreatLog>,
    pub dedup: Arc<Mutex<threat::Dedup>>,
    pid_file: Option<pid::PidFile>,
    shutdown_tx: Option<watch::Sender<bool>>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Monitor {
    /// Create a new Monitor from a loaded config.
    ///
    /// Does not write PID file, initialize CA, or start components.
    /// Call [`init()`](Self::init) then [`start()`](Self::start) to begin monitoring.
    pub fn new(config: config::Config) -> Self {
        let threat_log = Arc::new(threat::log::ThreatLog::new(&config.log_dir));
        let dedup = Arc::new(Mutex::new(threat::Dedup::new(config.dedup_window_secs)));
        Self {
            config,
            ca: None,
            threat_log,
            dedup,
            pid_file: None,
            shutdown_tx: None,
            handles: Vec::new(),
        }
    }

    /// Initialize CA and write PID file.
    ///
    /// Should be called once before [`start()`](Self::start).
    pub fn init(&mut self) -> anyhow::Result<()> {
        // PID file — single-instance enforcement
        let pid_file = pid::PidFile::new();
        pid_file.write()?;
        self.pid_file = Some(pid_file);

        // Initialize CA
        let ca = ca::CertAuthority::initialize(&self.config.log_dir, self.config.enable_mitm)?;
        self.ca = ca.map(Arc::new);

        info!(
            "ClawSec Monitor v3.0 — PID {} — MITM {}",
            std::process::id(),
            if self.ca.is_some() { "ON" } else { "OFF" }
        );

        Ok(())
    }

    /// Start the HTTP proxy and SSH watcher tasks.
    ///
    /// Must be called from within an active Tokio runtime.
    pub async fn start(&mut self) -> anyhow::Result<()> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let ca = self.ca.clone();
        let threat_log = self.threat_log.clone();
        let dedup = self.dedup.clone();

        // HTTP proxy
        if self.config.enable_http_proxy {
            let proxy = proxy::http::HttpProxy::new(
                self.config.http_proxy_port,
                self.config.max_scan_bytes,
                self.config.enable_mitm,
                ca.clone(),
                threat_log.clone(),
                dedup.clone(),
                shutdown_rx.clone(),
            );
            self.handles.push(tokio::spawn(async move {
                if let Err(e) = proxy.run().await {
                    tracing::warn!("HTTP proxy error: {}", e);
                }
            }));
        }

        // SSH watcher
        if self.config.enable_ssh_watcher {
            let mut watcher = ssh_watcher::SshWatcher::new(
                self.config.ssh_poll_interval,
                threat_log.clone(),
                dedup.clone(),
                shutdown_rx.clone(),
            );
            self.handles.push(tokio::spawn(async move {
                if let Err(e) = watcher.run().await {
                    tracing::warn!("SSH watcher error: {}", e);
                }
            }));
        }

        info!("All components started — {} task(s)", self.handles.len());
        Ok(())
    }

    /// Send shutdown signal and wait for all components to stop.
    pub async fn stop(&mut self) {
        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        // Wait for all tasks
        for h in self.handles.drain(..) {
            let _ = h.await;
        }
        // Clean up PID file
        if let Some(pid_file) = self.pid_file.take() {
            pid_file.remove();
        }
        info!("Monitor stopped.");
    }

    /// Returns a summary status (reads PID file).
    pub fn status(&self) -> Status {
        let running = pid::PidFile::new()
            .running_pid()
            .is_some();
        let pid = if running {
            pid::PidFile::new().running_pid()
        } else {
            None
        };
        let total_threats = self.read_threats(usize::MAX).len();
        Status {
            running,
            pid,
            total_threats,
        }
    }

    /// Read recent threats from the JSONL file.
    pub fn read_threats(&self, limit: usize) -> Vec<serde_json::Value> {
        let path = config::default_log_dir().join("threats.jsonl");
        match std::fs::read_to_string(&path) {
            Ok(content) => content
                .lines()
                .filter_map(|l| {
                    let l = l.trim();
                    if l.is_empty() {
                        None
                    } else {
                        serde_json::from_str(l).ok()
                    }
                })
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .take(limit)
                .rev()
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// Setup tracing/logging. Should be called once at startup.
pub fn setup_logging(cfg: &config::Config) {
    let _ = std::fs::create_dir_all(&cfg.log_dir);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cfg.log_level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("INFO")),
        )
        .with_writer(std::io::stderr)
        .init();
}

/// Send SIGTERM to a running monitor process. Used by `clawsec stop`.
pub fn stop_monitor_process() -> anyhow::Result<()> {
    let pid_file = pid::PidFile::new();
    match pid_file.running_pid() {
        Some(pid) => {
            println!("Sending SIGTERM to PID {pid}...");
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
            if pid_file.running_pid().is_none() {
                println!("Stopped.");
                pid_file.remove();
            } else {
                println!("Timeout, sending SIGKILL.");
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
                pid_file.remove();
            }
        }
        None => {
            println!("Not running.");
        }
    }
    Ok(())
}

/// Check if a monitor process is currently running.
pub fn is_monitor_running() -> bool {
    pid::PidFile::new().running_pid().is_some()
}
