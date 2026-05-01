use chrono::Utc;
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Type of threat detected.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ThreatType {
    #[serde(rename = "EXFIL")]
    Exfil,
    #[serde(rename = "INJECTION")]
    Injection,
    #[serde(rename = "SSH_CONNECT")]
    SshConnect,
}

/// A single detected threat event.
#[derive(Debug, Clone, Serialize)]
pub struct Threat {
    pub direction: String,
    pub protocol: String,
    pub threat_type: ThreatType,
    pub pattern: String,
    pub snippet: String,
    /// Full request/response text that was scanned (up to max_scan bytes).
    pub raw_payload: String,
    pub source: String,
    pub dest: String,
    pub timestamp: String,
}

impl Threat {
    pub fn new(
        direction: &str,
        protocol: &str,
        threat_type: ThreatType,
        pattern: &str,
        snippet: &str,
        raw_payload: &str,
        source: &str,
        dest: &str,
    ) -> Self {
        let snippet = if snippet.len() > 200 {
            snippet[..200].to_string()
        } else {
            snippet.to_string()
        };

        Self {
            direction: direction.to_string(),
            protocol: protocol.to_string(),
            threat_type,
            pattern: pattern.to_string(),
            snippet,
            raw_payload: raw_payload.to_string(),
            source: source.to_string(),
            dest: dest.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    /// Deduplication key: (pattern, dest, direction) tuple.
    pub fn dedup_key(&self) -> String {
        format!("{}:{}:{}", self.pattern, self.dest, self.direction)
    }
}

/// Deduplication engine.
///
/// Suppresses repeated (pattern, dest, direction) tuples within a
/// configurable rolling time window.
pub struct Dedup {
    window: Duration,
    seen: HashMap<String, Instant>,
}

impl Dedup {
    pub fn new(window_secs: f64) -> Self {
        Self {
            window: Duration::from_secs_f64(window_secs),
            seen: HashMap::new(),
        }
    }

    /// Returns `true` if this threat is a duplicate (should be suppressed).
    pub fn is_duplicate(&mut self, threat: &Threat) -> bool {
        let key = threat.dedup_key();
        let now = Instant::now();

        if let Some(last) = self.seen.get(&key) {
            if now.duration_since(*last) < self.window {
                return true;
            }
        }

        self.seen.insert(key, now);
        false
    }
}

pub mod log;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn dedup_suppresses_duplicate() {
        let mut dedup = Dedup::new(60.0);
        let t = Threat::new(
            "outbound",
            "http",
            ThreatType::Exfil,
            "ai_api_key",
            "sk-ant-test",
            "sk-ant-test full payload",
            "src",
            "dest.com",
        );
        assert!(
            !dedup.is_duplicate(&t),
            "first occurrence should not be duplicate"
        );
        assert!(
            dedup.is_duplicate(&t),
            "second occurrence should be suppressed"
        );
    }

    #[test]
    fn dedup_allows_different_pattern() {
        let mut dedup = Dedup::new(60.0);
        let t1 = Threat::new(
            "outbound",
            "http",
            ThreatType::Exfil,
            "ai_api_key",
            "sk-ant-test",
            "sk-ant-test",
            "src",
            "dest.com",
        );
        let t2 = Threat::new(
            "outbound",
            "http",
            ThreatType::Exfil,
            "ssh_pubkey",
            "ssh-rsa AAAAB",
            "ssh-rsa AAAAB",
            "src",
            "dest.com",
        );
        assert!(!dedup.is_duplicate(&t1));
        assert!(
            !dedup.is_duplicate(&t2),
            "different pattern should not be duplicate"
        );
    }

    #[test]
    fn dedup_allows_different_dest() {
        let mut dedup = Dedup::new(60.0);
        let t1 = Threat::new(
            "outbound",
            "http",
            ThreatType::Exfil,
            "ai_api_key",
            "sk-ant-test",
            "sk-ant-test",
            "src",
            "dest1.com",
        );
        let t2 = Threat::new(
            "outbound",
            "http",
            ThreatType::Exfil,
            "ai_api_key",
            "sk-ant-test",
            "sk-ant-test",
            "src",
            "dest2.com",
        );
        assert!(!dedup.is_duplicate(&t1));
        assert!(
            !dedup.is_duplicate(&t2),
            "different dest should not be duplicate"
        );
    }

    #[test]
    fn dedup_expires_after_window() {
        let mut dedup = Dedup::new(0.05); // 50 ms window
        let t = Threat::new(
            "outbound",
            "http",
            ThreatType::Exfil,
            "ai_api_key",
            "sk-ant-test",
            "sk-ant-test",
            "src",
            "dest.com",
        );
        assert!(!dedup.is_duplicate(&t));
        assert!(dedup.is_duplicate(&t));
        std::thread::sleep(Duration::from_millis(60));
        assert!(!dedup.is_duplicate(&t), "should expire after window");
    }
}
