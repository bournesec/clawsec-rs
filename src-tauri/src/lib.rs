use clawsec_core::{config::Config, Monitor, Status};
use std::sync::Arc;
use tokio::sync::Mutex;

struct AppState {
    monitor: Arc<Mutex<Option<Monitor>>>,
}

/// Path to the default config file location.
fn config_file_path() -> std::path::PathBuf {
    let cfg = Config::default();
    cfg.log_dir.join("config.json")
}

#[tauri::command]
async fn get_status(state: tauri::State<'_, AppState>) -> Result<Status, String> {
    let guard = state.monitor.lock().await;
    match &*guard {
        Some(m) => Ok(m.status()),
        None => {
            // Check if CLI-started monitor is running
            let running = clawsec_core::is_monitor_running();
            let pid = if running {
                clawsec_core::pid::PidFile::new().running_pid()
            } else {
                None
            };
            // Try to read threats from file
            let temp = Monitor::new(Config::default());
            let total = temp.read_threats(usize::MAX).len();
            Ok(Status {
                running,
                pid,
                total_threats: total,
            })
        }
    }
}

#[tauri::command]
async fn start_monitor(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.monitor.lock().await;

    if guard.is_some() {
        return Err("Monitor is already running in this session".into());
    }

    if clawsec_core::is_monitor_running() {
        return Err("Monitor is already running (started by CLI)".into());
    }

    // Setup logging before creating monitor
    clawsec_core::setup_logging(&Config::default());

    let mut monitor = Monitor::new(Config::default());
    monitor.init().map_err(|e| format!("Init failed: {e}"))?;
    monitor
        .start()
        .await
        .map_err(|e| format!("Start failed: {e}"))?;

    *guard = Some(monitor);
    Ok(())
}

#[tauri::command]
async fn stop_monitor(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.monitor.lock().await;
    if let Some(m) = guard.as_mut() {
        m.stop().await;
    }
    *guard = None;
    Ok(())
}

#[tauri::command]
async fn get_threats(
    state: tauri::State<'_, AppState>,
    limit: Option<usize>,
) -> Result<Vec<serde_json::Value>, String> {
    let l = limit.unwrap_or(50);
    let guard = state.monitor.lock().await;
    match &*guard {
        Some(m) => Ok(m.read_threats(l)),
        None => {
            let temp = Monitor::new(Config::default());
            Ok(temp.read_threats(l))
        }
    }
}

#[tauri::command]
async fn get_config() -> Result<Config, String> {
    let path = config_file_path();
    let cfg = if path.exists() {
        Config::from_file(&path).map_err(|e| format!("Failed to read config: {e}"))?
    } else {
        Config::default()
    };
    Ok(cfg)
}

#[tauri::command]
async fn save_config(config: Config) -> Result<(), String> {
    let path = config_file_path();
    // Create parent dir
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create config dir: {e}"))?;
    }
    let json = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("Failed to write config: {e}"))?;
    Ok(())
}

#[tauri::command]
async fn get_config_path() -> Result<String, String> {
    Ok(config_file_path().to_string_lossy().to_string())
}

#[tauri::command]
async fn get_recent_threats(
    state: tauri::State<'_, AppState>,
    since_count: usize,
) -> Result<Vec<serde_json::Value>, String> {
    let l = 100;
    let guard = state.monitor.lock().await;
    let threats = match &*guard {
        Some(m) => m.read_threats(l),
        None => {
            let temp = Monitor::new(Config::default());
            temp.read_threats(l)
        }
    };
    // Return threats that are newer than the known count
    if since_count >= threats.len() {
        Ok(Vec::new())
    } else {
        Ok(threats[since_count..].to_vec())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            monitor: Arc::new(Mutex::new(None)),
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_monitor,
            stop_monitor,
            get_threats,
            get_config,
            save_config,
            get_config_path,
            get_recent_threats,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
