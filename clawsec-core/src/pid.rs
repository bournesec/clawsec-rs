use std::path::{Path, PathBuf};

const PID_FILE: &str = "/tmp/clawsec/monitor.pid";

/// Manage the PID file for single-instance enforcement.
///
/// The PID file is NOT cleaned up on drop — only explicitly via `remove()`.
/// This avoids accidental deletion by temporary `PidFile` instances (e.g. in
/// `cmd_status`). Stale PID files are detected by `running_pid()` which checks
/// actual process existence via `kill(pid, 0)`.
pub struct PidFile {
    path: PathBuf,
}

impl Default for PidFile {
    fn default() -> Self {
        Self::new()
    }
}

impl PidFile {
    pub fn new() -> Self {
        Self {
            path: PathBuf::from(PID_FILE),
        }
    }

    #[allow(dead_code)]
    pub fn new_with(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Check if a monitor process is currently running.
    /// Returns `Some(pid)` if running, `None` otherwise.
    pub fn running_pid(&self) -> Option<u32> {
        let content = std::fs::read_to_string(&self.path).ok()?;
        let pid: u32 = content.trim().parse().ok()?;
        // Check if process exists (Unix: kill with signal 0)
        // This works on macOS via libc
        let result = unsafe { libc::kill(pid as i32, 0) };
        if result == 0 {
            Some(pid)
        } else {
            None // Process doesn't exist (stale PID)
        }
    }

    /// Write the current process PID to the file.
    /// Returns an error if the file already exists with a running process.
    pub fn write(&self) -> anyhow::Result<()> {
        if let Some(pid) = self.running_pid() {
            anyhow::bail!("Already running (PID {pid})");
        }

        // Create directory if needed
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let pid = std::process::id();
        std::fs::write(&self.path, pid.to_string())?;
        Ok(())
    }

    /// Remove the PID file.
    pub fn remove(&self) {
        let _ = std::fs::remove_file(&self.path);
    }

    #[allow(dead_code)]
    /// Return the path to the PID file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn pid_write_and_check() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.pid");
        let pid = PidFile::new_with(path.clone());

        // No PID file exists yet
        assert!(pid.running_pid().is_none());

        // Write our own PID
        pid.write().unwrap();
        assert!(pid.running_pid().is_some());

        // Clean up
        pid.remove();
        assert!(pid.running_pid().is_none());
    }

    #[test]
    fn pid_detects_stale() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("stale.pid");

        // Write a PID that doesn't exist
        std::fs::write(&path, "99999999").unwrap();
        let pid = PidFile::new_with(path);
        assert!(
            pid.running_pid().is_none(),
            "stale PID should not be reported as running"
        );
    }

    #[test]
    fn pid_double_write_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("double.pid");
        let pid = PidFile::new_with(path.clone());

        // Write our PID first
        pid.write().unwrap();

        // Try writing again — should succeed because same PID is running
        // Actually, write() checks if running_pid() returns Some and errors.
        // Since it's our own process, it will see it as running.
        let pid2 = PidFile::new_with(path);
        assert!(pid2.write().is_err(), "double write should fail");
    }
}
