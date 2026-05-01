/// Pattern definitions for EXFIL and INJECTION detection.
///
/// Organized as static lazy vectors so regex compilation happens at most once.
use once_cell::sync::Lazy;
use regex::Regex;

pub struct Pattern {
    pub label: &'static str,
    pub regex: Regex,
}

/// EXFIL patterns — data leaving the agent.
pub static EXFIL: Lazy<Vec<Pattern>> = Lazy::new(|| {
    vec![
        Pattern {
            label: "ai_api_key",
            regex: Regex::new(r"(?i)sk-(live|pro|ant|gpt|test)[a-zA-Z0-9_-]{20,}").unwrap(),
        },
        Pattern {
            label: "aws_access_key",
            regex: Regex::new(r"(?i)(AKIA|ASIA)[0-9A-Z]{16}").unwrap(),
        },
        Pattern {
            label: "private_key_pem",
            regex: Regex::new(r"(?i)-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----").unwrap(),
        },
        Pattern {
            label: "ssh_key_file",
            regex: Regex::new(r"(?i)\.ssh/(id_rsa|id_ed25519|config|authorized_keys)").unwrap(),
        },
        Pattern {
            label: "unix_sensitive",
            regex: Regex::new(r"/etc/(passwd|shadow|sudoers)\b").unwrap(),
        },
        Pattern {
            label: "dotenv_file",
            regex: Regex::new(r"/(\.env|\.aws/credentials)\b").unwrap(),
        },
        Pattern {
            label: "ssh_pubkey",
            regex: Regex::new(r"ssh-rsa\s+[A-Za-z0-9+/=]{40,}").unwrap(),
        },
    ]
});

/// INJECTION patterns — commands arriving at the agent.
pub static INJECTION: Lazy<Vec<Pattern>> = Lazy::new(|| {
    vec![
        Pattern {
            label: "pipe_to_shell",
            regex: Regex::new(r"(?i)(curl|wget)\s+\S+\s*\|\s*(sh|bash)\b").unwrap(),
        },
        Pattern {
            label: "shell_exec",
            regex: Regex::new(r##"(?i)\b(bash|sh)\s+-[ci]\s+['"]"##).unwrap(),
        },
        Pattern {
            label: "reverse_shell",
            regex: Regex::new(r"\b(nc|netcat|ncat)\s+\S+\s+\d{2,5}\b").unwrap(),
        },
        Pattern {
            label: "destructive_rm",
            regex: Regex::new(r"\brm\s+-rf\s+/").unwrap(),
        },
        Pattern {
            label: "ssh_key_inject",
            regex: Regex::new(r"(?i)echo\s+ssh-rsa\b").unwrap(),
        },
    ]
});
