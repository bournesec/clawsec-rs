use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default configuration values.
pub fn default_log_dir() -> PathBuf {
    PathBuf::from("/tmp/clawsec")
}

pub const DEFAULT_HTTP_PROXY_PORT: u16 = 10808;
pub const DEFAULT_GATEWAY_LOCAL_PORT: u16 = 18790;
pub const DEFAULT_GATEWAY_TARGET_PORT: u16 = 18789;
pub const DEFAULT_MAX_SCAN_BYTES: usize = 65536;
pub const DEFAULT_SSH_POLL_INTERVAL: u64 = 10;
pub const DEFAULT_DEDUP_WINDOW_SECS: f64 = 60.0;
pub const DEFAULT_LOG_LEVEL: &str = "INFO";

/// Application configuration, loadable from a JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub http_proxy_port: u16,
    pub gateway_local_port: u16,
    pub gateway_target_port: u16,
    pub log_dir: PathBuf,
    pub log_level: String,
    pub max_scan_bytes: usize,
    pub ssh_poll_interval: u64,
    pub dedup_window_secs: f64,
    pub enable_http_proxy: bool,
    pub enable_gateway_proxy: bool,
    pub enable_ssh_watcher: bool,
    pub enable_mitm: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_proxy_port: DEFAULT_HTTP_PROXY_PORT,
            gateway_local_port: DEFAULT_GATEWAY_LOCAL_PORT,
            gateway_target_port: DEFAULT_GATEWAY_TARGET_PORT,
            log_dir: default_log_dir(),
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            max_scan_bytes: DEFAULT_MAX_SCAN_BYTES,
            ssh_poll_interval: DEFAULT_SSH_POLL_INTERVAL,
            dedup_window_secs: DEFAULT_DEDUP_WINDOW_SECS,
            enable_http_proxy: true,
            enable_gateway_proxy: true,
            enable_ssh_watcher: true,
            enable_mitm: true,
        }
    }
}

impl Config {
    /// Load config from a JSON file path. Missing keys fall back to defaults.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config: {}", path.display()))?;
        let cfg: Config = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse config: {}", path.display()))?;
        Ok(cfg)
    }

    /// Load config from an optional path, returning defaults if None.
    pub fn load(path: Option<&Path>) -> Self {
        match path {
            Some(p) => Self::from_file(p).unwrap_or_else(|e| {
                eprintln!("[warn] Could not load config {}: {}", p.display(), e);
                Config::default()
            }),
            None => Config::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.http_proxy_port, 10808);
        assert_eq!(cfg.max_scan_bytes, 65536);
        assert_eq!(cfg.dedup_window_secs, 60.0);
        assert!(cfg.enable_http_proxy);
    }

    #[test]
    fn config_load_from_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.json");

        let json = r#"{
            "http_proxy_port": 8889,
            "enable_ssh_watcher": false,
            "log_level": "DEBUG"
        }"#;
        std::fs::write(&path, json).unwrap();

        let cfg = Config::from_file(&path).unwrap();
        assert_eq!(cfg.http_proxy_port, 8889);
        assert!(!cfg.enable_ssh_watcher);
        assert_eq!(cfg.log_level, "DEBUG");
        // Defaults still apply for missing keys
        assert!(cfg.enable_http_proxy);
        assert_eq!(cfg.max_scan_bytes, 65536);
    }

    #[test]
    fn config_load_missing_file_falls_back() {
        let cfg = Config::load(Some(Path::new("/nonexistent/config.json")));
        assert_eq!(cfg.http_proxy_port, 10808);
        assert!(cfg.enable_http_proxy);
    }

    #[test]
    fn config_load_none() {
        let cfg = Config::load(None);
        assert_eq!(cfg.http_proxy_port, 10808);
    }
}
