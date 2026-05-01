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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_start_defaults() {
        let cli = Cli::try_parse_from(["clawsec", "start"]).unwrap();
        match cli.command {
            Commands::Start { config, no_mitm } => {
                assert!(config.is_none());
                assert!(!no_mitm);
            }
            _ => panic!("expected Start"),
        }
    }

    #[test]
    fn cli_start_with_config() {
        let cli =
            Cli::try_parse_from(["clawsec", "start", "--config", "/tmp/test.json"]).unwrap();
        match cli.command {
            Commands::Start { config, no_mitm } => {
                assert_eq!(config.unwrap(), std::path::PathBuf::from("/tmp/test.json"));
                assert!(!no_mitm);
            }
            _ => panic!("expected Start"),
        }
    }

    #[test]
    fn cli_start_no_mitm() {
        let cli = Cli::try_parse_from(["clawsec", "start", "--no-mitm"]).unwrap();
        match cli.command {
            Commands::Start { config, no_mitm } => {
                assert!(config.is_none());
                assert!(no_mitm);
            }
            _ => panic!("expected Start"),
        }
    }

    #[test]
    fn cli_stop() {
        let cli = Cli::try_parse_from(["clawsec", "stop"]).unwrap();
        assert!(matches!(cli.command, Commands::Stop));
    }

    #[test]
    fn cli_status() {
        let cli = Cli::try_parse_from(["clawsec", "status"]).unwrap();
        assert!(matches!(cli.command, Commands::Status));
    }

    #[test]
    fn cli_threats_default_limit() {
        let cli = Cli::try_parse_from(["clawsec", "threats"]).unwrap();
        match cli.command {
            Commands::Threats { limit } => assert_eq!(limit, 10),
            _ => panic!("expected Threats"),
        }
    }

    #[test]
    fn cli_threats_custom_limit() {
        let cli = Cli::try_parse_from(["clawsec", "threats", "--limit", "50"]).unwrap();
        match cli.command {
            Commands::Threats { limit } => assert_eq!(limit, 50),
            _ => panic!("expected Threats"),
        }
    }
}
