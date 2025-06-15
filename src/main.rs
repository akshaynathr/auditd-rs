mod cli;
mod config;
mod ebpf;
mod logging;
mod reporting;

use anyhow::Result;
use chrono::NaiveDate;
use clap::Parser;
use cli::{Cli, Commands};
use config::AuditConfig;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { config } => {
            let default_config = AuditConfig::default();
            std::fs::write(&config, serde_yaml::to_string(&default_config)?)?;
            println!("Initialized configuration at {}", config.display());
        }
        Commands::Run { config } => {
            let config_content = std::fs::read_to_string(&config)?;
            let audit_config: AuditConfig = serde_yaml::from_str(&config_content)?;
            
            let ebpf_manager = Arc::new(Mutex::new(ebpf::EbpfManager::new().await?));
            let _log_manager = Arc::new(Mutex::new(logging::LogManager::new(audit_config.log_dir)?));

            println!("Starting audit monitoring...");
            let mut ebpf = ebpf_manager.lock().await;
            ebpf.attach_probes().await?;

            // Keep the program running
            tokio::signal::ctrl_c().await?;
            println!("Shutting down...");
            ebpf.detach_probes().await;
        }
        Commands::Status => {
            // TODO: Implement status check
            println!("Status: Not implemented yet");
        }
        Commands::Report {
            from,
            to,
            format,
            output,
        } => {
            let from_date = NaiveDate::parse_from_str(&from, "%Y-%m-%d")?;
            let to_date = NaiveDate::parse_from_str(&to, "%Y-%m-%d")?;
            
            let report_generator = reporting::ReportGenerator::new(PathBuf::from("/var/log/auditrust"));
            report_generator
                .generate_report(
                    from_date.and_hms_opt(0, 0, 0).unwrap().and_utc(),
                    to_date.and_hms_opt(23, 59, 59).unwrap().and_utc(),
                    &format,
                    output,
                )
                .await?;
        }
    }

    Ok(())
} 