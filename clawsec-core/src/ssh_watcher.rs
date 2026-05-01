use crate::threat::Dedup;
use crate::threat::{Threat, ThreatType};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::watch;
use tracing::{debug, info};

/// Polls macOS `netstat -tn` for new established SSH connections.
pub struct SshWatcher {
    poll_interval: u64,
    seen: HashSet<String>,
    threat_log: Arc<crate::threat::log::ThreatLog>,
    dedup: Arc<tokio::sync::Mutex<Dedup>>,
    shutdown: watch::Receiver<bool>,
}

impl SshWatcher {
    pub fn new(
        poll_interval: u64,
        threat_log: Arc<crate::threat::log::ThreatLog>,
        dedup: Arc<tokio::sync::Mutex<Dedup>>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            poll_interval,
            seen: HashSet::new(),
            threat_log,
            dedup,
            shutdown,
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut shutdown = self.shutdown.clone();
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    info!("SSH watcher shutting down...");
                    break;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(self.poll_interval)) => {
                    let current = self.get_ssh_connections().await;
                    match current {
                        Ok(conns) => {
                            for conn in &conns {
                                if !self.seen.contains(conn) {
                                    let t = Threat::new(
                                        "outbound",
                                        "ssh",
                                        ThreatType::SshConnect,
                                        "established_connection",
                                        conn,
                                        conn,
                                        "",
                                        "",
                                    );
                                    let mut d = self.dedup.lock().await;
                                    if !d.is_duplicate(&t) {
                                        let _ = self.threat_log.append(&t);
                                    }
                                }
                            }
                            self.seen = conns;
                        }
                        Err(e) => {
                            debug!("SSH watcher error: {}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Run `netstat -tn` and parse established SSH connections.
    async fn get_ssh_connections(&self) -> anyhow::Result<HashSet<String>> {
        let output = Command::new("netstat").args(["-tn"]).output().await?;

        let text = String::from_utf8_lossy(&output.stdout);
        let mut conns = HashSet::new();

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            // Expected format (6+ fields):
            // tcp4 0 0 192.168.1.5.54322 10.0.0.1.22 ESTABLISHED
            // index:             0 1 2        3              4           5
            if parts.len() >= 6 && parts.last() == Some(&"ESTABLISHED") {
                let local = parts[parts.len() - 3];
                let remote = parts[parts.len() - 2];
                // Only capture outbound SSH connections (local → remote:22)
                if remote.contains(".22") {
                    conns.insert(format!("{} -> {}", local, remote));
                }
            }
        }

        Ok(conns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::log::ThreatLog;
    use tempfile::TempDir;
    use tokio::sync::watch;

    #[test]
    fn new_initializes_fields() {
        let dir = TempDir::new().unwrap();
        let log = Arc::new(ThreatLog::new(dir.path()));
        let dedup = Arc::new(tokio::sync::Mutex::new(Dedup::new(60.0)));
        let (_tx, rx) = watch::channel(false);

        let watcher = SshWatcher::new(5, log.clone(), dedup.clone(), rx);

        assert_eq!(watcher.poll_interval, 5);
        assert!(watcher.seen.is_empty());
    }

    #[tokio::test]
    async fn run_exits_on_shutdown_signal() {
        let dir = TempDir::new().unwrap();
        let log = Arc::new(ThreatLog::new(dir.path()));
        let dedup = Arc::new(tokio::sync::Mutex::new(Dedup::new(60.0)));
        let (tx, rx) = watch::channel(false);

        let mut watcher = SshWatcher::new(3600, log, dedup, rx);

        // Send shutdown immediately
        let handle = tokio::spawn(async move {
            watcher.run().await.unwrap();
        });

        // Give it a moment to enter the loop, then signal shutdown
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        tx.send(true).unwrap();

        // Wait for run() to exit with a timeout
        match tokio::time::timeout(tokio::time::Duration::from_secs(5), handle).await {
            Ok(Ok(())) => {} // Success: run() exited cleanly
            Ok(Err(e)) => panic!("run() task panicked: {:?}", e),
            Err(_) => panic!("run() did not exit within timeout"),
        }
    }
}
