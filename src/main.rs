use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;

/// ClawSec Monitor v3.0 — AI Agent Traffic Inspector
#[derive(Parser)]
#[command(name = "clawsec", version = "3.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the monitor (foreground)
    Start {
        /// JSON config file path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Disable HTTPS interception (blind CONNECT tunnel)
        #[arg(long)]
        no_mitm: bool,
    },
    /// Stop a running monitor
    Stop,
    /// Show status and recent threats
    Status,
    /// Dump recent threats as JSON
    Threats {
        /// Max number of recent threats to show
        #[arg(long, default_value = "10")]
        limit: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Start { config, no_mitm } => cmd_start(config, no_mitm),
        Commands::Stop => clawsec_core::stop_monitor_process(),
        Commands::Status => cmd_status(),
        Commands::Threats { limit } => cmd_threats(limit),
    }
}

fn cmd_start(config_path: Option<PathBuf>, no_mitm: bool) -> anyhow::Result<()> {
    let mut cfg = clawsec_core::config::Config::load(config_path.as_deref());
    if no_mitm {
        cfg.enable_mitm = false;
    }

    clawsec_core::setup_logging(&cfg);

    let mut monitor = clawsec_core::Monitor::new(cfg);
    monitor.init()?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        monitor.start().await?;

        info!("Ready — press Ctrl-C to stop.");

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down gracefully...");
            }
        }

        monitor.stop().await;
        anyhow::Ok(())
    })?;

    Ok(())
}

fn cmd_status() -> anyhow::Result<()> {
    if clawsec_core::is_monitor_running() {
        let pid = clawsec_core::pid::PidFile::new()
            .running_pid()
            .unwrap_or(0);
        println!("ClawSec Monitor: RUNNING (PID {pid})");
    } else {
        println!("ClawSec Monitor: STOPPED");
    }
    cmd_threats(5)?;
    Ok(())
}

fn cmd_threats(limit: usize) -> anyhow::Result<()> {
    let monitor = clawsec_core::Monitor::new(clawsec_core::config::Config::default());
    let threats = monitor.read_threats(limit);
    if threats.is_empty() {
        println!("[]");
    } else {
        println!("{}", serde_json::to_string_pretty(&threats).unwrap_or_default());
    }
    Ok(())
}
