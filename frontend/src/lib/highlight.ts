/**
 * Highlight the matched attack payload within a snippet.
 *
 * Uses pattern-specific regexes (mirroring backend `scanner/patterns.rs`)
 * to locate the actual matched payload, wraps it in a red-background
 * `<mark>`, and returns safe HTML.  Non-matching context is left unstyled.
 */

/** HTML-escape user-controlled text before injection into the DOM. */
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Regexes that mirror the backend patterns in `clawsec-core/src/scanner/patterns.rs`.
 * Keep these in sync with the Rust definitions.
 */
const PAYLOAD_RE: Record<string, RegExp> = {
  // ── EXFIL ──────────────────────────────────────────────────────────
  ai_api_key: /sk-(?:live|pro|ant|gpt|test)[a-zA-Z0-9_-]{20,}/gi,
  aws_access_key: /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
  private_key_pem: /-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----/gi,
  ssh_key_file: /\.ssh\/(?:id_rsa|id_ed25519|config|authorized_keys)/gi,
  unix_sensitive: /\/etc\/(?:passwd|shadow|sudoers)\b/g,
  dotenv_file: /\/(?:\.env|\.aws\/credentials)\b/g,
  ssh_pubkey: /ssh-rsa\s+[A-Za-z0-9+/=]{40,}/gi,

  // ── INJECTION ──────────────────────────────────────────────────────
  pipe_to_shell: /(?:curl|wget)\s+\S+\s*\|\s*(?:sh|bash)\b/gi,
  shell_exec: /\b(?:bash|sh)\s+-[ci]\s+['"][^'"]*['"]/gi,
  reverse_shell: /\b(?:nc|netcat|ncat)\s+\S+\s+\d{2,5}\b/gi,
  destructive_rm: /\brm\s+-rf\s+\//g,
  ssh_key_inject: /echo\s+ssh-rsa\b/gi,
};

const MARK_STYLE =
  "background:var(--color-danger-soft);color:var(--color-danger);border-radius:3px;padding:1px 3px;font-weight:600;";

/**
 * Return safe HTML where the first regex match in `snippet` for the given
 * `pattern` label is wrapped in a styled `<mark>`.  If the pattern is
 * unknown or nothing matches, the escaped snippet is returned as-is.
 */
export function highlightPayload(snippet: string, pattern: string): string {
  const escaped = escapeHtml(snippet);
  const re = PAYLOAD_RE[pattern];
  if (!re) return escaped;

  // Reset lastIndex for global regexes
  re.lastIndex = 0;

  const m = re.exec(escaped);
  if (!m) return escaped;

  const before = escaped.slice(0, m.index);
  const hit = escaped.slice(m.index, m.index + m[0].length);
  const after = escaped.slice(m.index + m[0].length);

  return `${before}<mark style="${MARK_STYLE}">${hit}</mark>${after}`;
}
